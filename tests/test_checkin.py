import contextlib
import io
import json
import os
import unittest
from unittest import mock

import requests

import checkin


COOKIE = "gld:sess=test-session; gld:sess.sig=test-signature; optional=keep"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0"


def response(payload=None, status=200, text=None):
    result = requests.Response()
    result.status_code = status
    result.url = checkin.CHECKIN_URL
    result._content = (text if text is not None else json.dumps(payload)).encode()
    return result


class CookieTests(unittest.TestCase):
    def test_current_and_legacy_sessions_are_preserved(self):
        for cookie in (COOKIE, "koa:sess=old; koa:sess.sig=signature", "koa:sess=old; " + COOKIE):
            with self.subTest(cookie=cookie):
                self.assertTrue(checkin.validate_cookie(cookie)[0])
                self.assertEqual(checkin.parse_cookies(cookie), [cookie])

    def test_incomplete_empty_or_mixed_sessions_are_rejected(self):
        for cookie in ("", "gld:sess=value", "gld:sess=; gld:sess.sig=value",
                       "gld:sess=value; koa:sess.sig=value", "fakegld:sess=value; fakegld:sess.sig=value"):
            with self.subTest(cookie=cookie):
                self.assertFalse(checkin.validate_cookie(cookie)[0])

    def test_request_header_copy_is_normalized(self):
        self.assertEqual(checkin.parse_cookies(f'"Cookie: {COOKIE}"'), [COOKIE])

    def test_existing_and_new_account_separators(self):
        for separator in ("&", "\n", "\r\n", "|||"):
            with self.subTest(separator=separator):
                self.assertEqual(checkin.parse_cookies(COOKIE + separator + COOKIE), [COOKIE, COOKIE])

    def test_cookie_values_are_fully_masked(self):
        self.assertEqual(checkin.mask_cookie(COOKIE), "***")


class ResultTests(unittest.TestCase):
    def test_auth_and_device_errors_are_never_success_or_repeat(self):
        for code, message, reason in (
            (-2, "没有权限", ""), (1, "没有权限", ""),
            (1, "Automated check-in detected", "device-mismatch"),
            (0, "unauthorized", ""), (1, "please checkin via https://glados.cloud", ""),
            (1, "unknown response", ""), (-2, "Checkin! Got 20 Points", ""),
        ):
            with self.subTest(code=code, message=message):
                self.assertEqual(checkin.classify_checkin(code, message, reason), "fail")

    def test_explicit_repeat_is_successful_repeat(self):
        self.assertEqual(checkin.classify_checkin(1, "Checkin Repeats! Please Try Tomorrow"), "repeat")

    def test_historic_and_current_success_messages(self):
        for code, message in ((0, "Checkin! Got 15 Points"),
                              (1, "Today's observation logged. You've earned 20 points."),
                              (0, "已经签到成功，获得 1 点，请明天继续签到哦！")):
            with self.subTest(message=message):
                self.assertEqual(checkin.classify_checkin(code, message), "ok")

    def test_device_error_includes_actionable_configuration_names(self):
        message = checkin.failure_message({"reason": "device-mismatch"})
        self.assertIn("COOKIES", message)
        self.assertIn("GLADOS_USER_AGENT", message)


class RequestTests(unittest.TestCase):
    @mock.patch("checkin.time.sleep")
    def test_transient_http_error_is_retried(self, sleep):
        session = mock.Mock()
        session.post.side_effect = [response(status=503, text="<html>unavailable</html>"),
                                    response({"code": 0, "message": "Checkin! Got 20 Points"})]
        self.assertEqual(checkin.checkin_request(session, {})["code"], 0)
        self.assertEqual(session.post.call_count, 2)
        sleep.assert_called_once()

    @mock.patch("checkin.time.sleep")
    def test_auth_http_error_is_not_retried(self, sleep):
        session = mock.Mock()
        session.post.return_value = response({"code": -2, "message": "没有权限"}, status=401)
        with self.assertRaises(requests.HTTPError):
            checkin.checkin_request(session, {})
        self.assertEqual(session.post.call_count, 1)
        sleep.assert_not_called()

    @mock.patch("checkin.time.sleep")
    def test_rate_limit_is_retried(self, sleep):
        session = mock.Mock()
        session.post.side_effect = [response(status=429, text="slow down"), response({"code": 0})]
        self.assertEqual(checkin.checkin_request(session, {})["code"], 0)
        self.assertEqual(session.post.call_count, 2)

    def test_html_and_non_object_json_cannot_report_success(self):
        for result in (response(text="<html>login required</html>"), response([{"code": 0}])):
            with self.assertRaises(requests.RequestException):
                checkin.api_json(result)


class AccountTests(unittest.TestCase):
    def session(self, checkin_result):
        session = mock.Mock()
        session.get.side_effect = [
            response({"code": 0, "data": {"email": "test@example.com", "leftDays": "247.5"}}),
            response({"code": 0, "data": {"leftDays": "247.5"}}),
            response({"points": 331}),
        ]
        session.post.return_value = response(checkin_result)
        return session

    def test_full_cookie_and_login_browser_are_sent(self):
        session = self.session({"code": 1, "message": "Today's observation logged. You've earned 20 points."})
        with mock.patch.dict(os.environ, {"GLADOS_USER_AGENT": USER_AGENT}):
            account = checkin.checkin_account(session, COOKIE, 1)
        self.assertEqual(account["status"], "✅ 成功 (+20积分)")
        self.assertEqual(account["total_points"], "331 积分")
        self.assertEqual(account["remaining_days"], "247 天")
        headers = session.post.call_args.kwargs["headers"]
        self.assertEqual(headers["cookie"], COOKIE)
        self.assertEqual(headers["user-agent"], USER_AGENT)

    def test_invalid_login_does_not_submit_checkin(self):
        session = mock.Mock()
        session.get.return_value = response({"code": -2, "message": "没有权限"})
        account = checkin.checkin_account(session, COOKIE, 1)
        self.assertIn("❌", account["status"])
        self.assertIn("更新 COOKIES", account["status"])
        session.post.assert_not_called()
        self.assertEqual(session.get.call_count, 1)

    def test_device_mismatch_is_failure_after_valid_login(self):
        session = self.session({"code": 1, "message": "Automated check-in detected", "reason": "device-mismatch"})
        account = checkin.checkin_account(session, COOKIE, 1)
        self.assertIn("❌", account["status"])
        self.assertIn("GLADOS_USER_AGENT", account["status"])


class MainTests(unittest.TestCase):
    def run_main(self, cookies, results=()):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"COOKIES": cookies}, clear=True), \
             mock.patch("checkin.push_all") as push, \
             mock.patch("checkin.time.sleep"), \
             mock.patch("checkin.requests.Session") as session, \
             mock.patch("checkin.checkin_account", side_effect=results) as account, \
             contextlib.redirect_stdout(output):
            code = checkin.main()
        return code, output.getvalue(), session, account, push

    def result(self, status):
        return {"index": 1, "email": "unknown", "status": status, "total_points": "-", "remaining_days": "-"}

    def test_missing_configuration_returns_failure(self):
        code, _, session, _, _ = self.run_main("")
        self.assertEqual(code, 1)
        session.assert_not_called()

    def test_invalid_cookie_returns_failure_without_exposing_values(self):
        cookie = "gld:sess=PRIVATE-TEST-VALUE"
        code, output, session, account, _ = self.run_main(cookie)
        self.assertEqual(code, 1)
        self.assertNotIn("PRIVATE-TEST-VALUE", output)
        session.assert_not_called()
        account.assert_not_called()

    def test_failed_account_returns_failure(self):
        code, _, _, _, _ = self.run_main(COOKIE, [self.result("❌ 失败(没有权限)")])
        self.assertEqual(code, 1)

    def test_success_and_repeat_return_success(self):
        code, _, session, _, _ = self.run_main(COOKIE + "&" + COOKIE,
                                             [self.result("✅ 成功"), self.result("🔄 已签到")])
        self.assertEqual(code, 0)
        self.assertEqual(session.call_count, 2)

    def test_one_failure_among_successes_fails_the_run(self):
        code, _, _, _, _ = self.run_main(COOKIE + "&" + COOKIE,
                                       [self.result("✅ 成功"), self.result("❌ 失败")])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
