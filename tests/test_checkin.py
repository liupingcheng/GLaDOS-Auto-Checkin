import contextlib
import io
import json
import os
import unittest
from unittest import mock

import requests

import checkin
from browser_checkin import (
    BrowserFlowError, browser_cookies, validate_submission,
    turnstile_error_code, turnstile_response_diagnostics,
)


COOKIE = "gld:sess=test-session; gld:sess.sig=test-signature; optional=keep"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0"


def response(payload=None, status=200, text=None):
    result = requests.Response()
    result.status_code = status
    result.url = checkin.CHECKIN_URL
    result._content = (text if text is not None else json.dumps(payload)).encode()
    return result


def challenge(nonce="browser-reference-nonce", **fields):
    return response({"code": 0, "nonce": nonce, "ttl": 300000, **fields})


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

    def test_live_return_tomorrow_response_is_already_checked_in(self):
        self.assertEqual(checkin.classify_checkin(
            1, "Today's observation logged. Return tomorrow for more points."
        ), "repeat")

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
    def session(self):
        session = mock.Mock()
        session.get.side_effect = lambda *a, **kw: challenge()
        return session

    @mock.patch("checkin.time.sleep")
    def test_transient_http_error_is_retried(self, sleep):
        session = self.session()
        session.post.side_effect = [response(status=503, text="<html>unavailable</html>"),
                                    response({"code": 0, "message": "Checkin! Got 20 Points"})]
        self.assertEqual(checkin.checkin_request(session, {})["code"], 0)
        self.assertEqual(session.post.call_count, 2)
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(sleep.call_args_list, [mock.call(2.7), mock.call(2.0), mock.call(2.7)])

    @mock.patch("checkin.time.sleep")
    def test_auth_http_error_is_not_retried(self, sleep):
        session = self.session()
        session.post.return_value = response({"code": -2, "message": "没有权限"}, status=401)
        with self.assertRaises(requests.HTTPError):
            checkin.checkin_request(session, {})
        self.assertEqual(session.post.call_count, 1)
        sleep.assert_called_once_with(2.7)

    @mock.patch("checkin.time.sleep")
    def test_rate_limit_is_retried(self, sleep):
        session = self.session()
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
            challenge(),
            response({"code": 0, "data": {"leftDays": "247.5"}}),
            response({"points": 331}),
        ]
        session.post.return_value = response(checkin_result)
        return session

    @mock.patch("checkin.time.sleep")
    def test_full_cookie_and_login_browser_are_sent(self, sleep):
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

    @mock.patch("checkin.time.sleep")
    def test_device_mismatch_is_failure_after_valid_login(self, sleep):
        session = self.session({"code": 1, "message": "Automated check-in detected", "reason": "device-mismatch"})
        account = checkin.checkin_account(session, COOKIE, 1)
        self.assertIn("❌", account["status"])
        self.assertIn("GLADOS_USER_AGENT", account["status"])


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        clock = mock.patch("checkin.time.monotonic", side_effect=lambda: self.now)
        wait = mock.patch("checkin.time.sleep", side_effect=self.advance)
        clock.start()
        self.sleep = wait.start()
        self.addCleanup(clock.stop)
        self.addCleanup(wait.stop)

    def advance(self, delay):
        self.now += delay

    def session(self):
        session = mock.Mock()
        session.get.return_value = challenge()
        session.post.return_value = response({"code": 0, "message": "Checkin! Got 12 Points", "points": 12})
        return session

    def test_browser_reference_payload_and_wait(self):
        session = self.session()
        self.assertEqual(checkin.checkin_request(session, {"cookie": COOKIE})["points"], 12)
        self.sleep.assert_called_once_with(2.7)
        payload = json.loads(session.post.call_args.kwargs["data"])
        self.assertEqual(payload, {
            "token": "glados.cloud", "nonce": "browser-reference-nonce", "tsState": "off",
            "proof": "7d4d4eeb87b7d4e9f358ef166b3ad76d595c7ca862291d544ca76b262e2ae71d",
        })
        self.assertEqual(session.get.call_args.args, (checkin.CHALLENGE_URL,))
        self.assertEqual(session.post.call_args.args, (checkin.CHECKIN_URL,))
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertFalse(session.post.call_args.kwargs["allow_redirects"])
        self.assertEqual(session.get.call_args.kwargs["headers"], session.post.call_args.kwargs["headers"])

    def test_utf8_nonce_matches_browser_reference(self):
        session = self.session()
        session.get.return_value = challenge("测试-nonce-α")
        checkin.checkin_request(session, {})
        self.assertEqual(json.loads(session.post.call_args.kwargs["data"])["proof"],
                         "ad866a617e8e6b5363517ebb55937be9e36485b299dfcec5efc534b2d94b13a7")

    def test_bad_nonce_stops_without_token_only_fallback(self):
        for nonce in (None, "", "  ", 17, {}, "x" * 4097):
            with self.subTest(nonce_type=type(nonce).__name__):
                session = self.session()
                session.get.return_value = challenge(nonce)
                with self.assertRaises(checkin.CheckinProtocolError):
                    checkin.checkin_request(session, {})
                session.post.assert_not_called()
                self.assertEqual(session.get.call_count, 1)

    def test_bad_or_too_short_ttl_stops_submission(self):
        for ttl in (None, False, 0, -1, "300000", {}, float("nan"), float("inf"), 17000):
            with self.subTest(ttl=ttl):
                session = self.session()
                session.get.return_value = challenge(ttl=ttl)
                with self.assertRaises(checkin.CheckinProtocolError):
                    checkin.checkin_request(session, {})
                session.post.assert_not_called()

    def test_missing_ttl_uses_official_default(self):
        session = self.session()
        session.get.return_value = response({"code": 0, "nonce": "browser-reference-nonce"})
        self.assertEqual(checkin.checkin_request(session, {})["code"], 0)

    def test_expiry_during_wait_stops_submission(self):
        session = self.session()
        self.sleep.side_effect = lambda delay: self.advance(300)
        with self.assertRaisesRegex(checkin.CheckinProtocolError, "过期"):
            checkin.checkin_request(session, {})
        session.post.assert_not_called()

    def test_fetch_latency_counts_towards_expiry(self):
        session = self.session()
        def slow_get(*args, **kwargs):
            self.advance(290)
            return challenge()
        session.get.side_effect = slow_get
        with self.assertRaises(checkin.CheckinProtocolError):
            checkin.checkin_request(session, {})
        session.post.assert_not_called()

    @mock.patch("browser_checkin.browser_checkin", side_effect=BrowserFlowError("Turnstile 未通过"))
    def test_turnstile_is_not_faked_or_downgraded(self, browser):
        for config in ({"sitekey": "public-site-key"}, {}, True):
            session = self.session()
            session.get.return_value = challenge(turnstile=config)
            with self.assertRaisesRegex(checkin.CheckinProtocolError, "Turnstile"):
                checkin.checkin_request(session, {})
            session.post.assert_not_called()
            self.assertEqual(session.get.call_count, 1)
        self.assertEqual(browser.call_count, 3)

    @mock.patch("browser_checkin.browser_checkin")
    def test_browser_adapter_does_not_post_old_payload_and_redacts_token(self, browser):
        session = self.session()
        session.get.return_value = challenge(turnstile={"sitekey": "public"})
        browser.return_value = ({"code": 1, "message": "test-nonce test-proof test-turnstile"},
                                ["test-nonce", "test-proof", "test-turnstile"])
        result = checkin.checkin_request(session, {"cookie": COOKIE})
        self.assertEqual(result["message"], "*** *** ***")
        session.post.assert_not_called()
        self.sleep.assert_not_called()
        browser.assert_called_once_with({"cookie": COOKIE}, checkin.CHECKIN_URL, checkin.CHALLENGE_URL)

    def test_logical_challenge_rejection_is_not_retried(self):
        for code in (-2, 4, False, "0", None):
            session = self.session()
            session.get.return_value = response({"code": code, "message": "sensitive-nonce"})
            with self.assertRaises(checkin.CheckinProtocolError) as exc:
                checkin.checkin_request(session, {})
            self.assertNotIn("sensitive-nonce", str(exc.exception))
            session.post.assert_not_called()
            self.assertEqual(session.get.call_count, 1)

    def test_challenge_http_auth_rejection_is_not_retried(self):
        session = self.session()
        session.get.return_value = response(status=403, text="forbidden")
        with self.assertRaises(requests.HTTPError):
            checkin.checkin_request(session, {})
        session.post.assert_not_called()
        self.assertEqual(session.get.call_count, 1)

    def test_http_retry_fetches_new_nonce_and_proof(self):
        session = self.session()
        session.get.side_effect = [challenge("first-nonce"), challenge("second-nonce")]
        session.post.side_effect = [response(status=503, text="unavailable"), response({"code": 0})]
        checkin.checkin_request(session, {})
        payloads = [json.loads(call.kwargs["data"]) for call in session.post.call_args_list]
        self.assertEqual([p["nonce"] for p in payloads], ["first-nonce", "second-nonce"])
        self.assertNotEqual(payloads[0]["proof"], payloads[1]["proof"])
        self.assertEqual(session.get.call_count, 2)

    def test_get_retry_does_not_post_until_new_challenge_is_available(self):
        session = self.session()
        session.get.side_effect = [response(status=503, text="unavailable"), challenge()]
        checkin.checkin_request(session, {})
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(session.post.call_count, 1)

    def test_redirect_and_cross_origin_responses_are_rejected(self):
        for phase in ("get", "post"):
            for redirected in (response(status=302, text="redirect"), response({"code": 0})):
                if redirected.status_code == 200:
                    redirected.url = "https://other.example/api/user/checkin"
                session = self.session()
                getattr(session, phase).return_value = redirected
                with self.assertRaises(checkin.CheckinProtocolError):
                    checkin.checkin_request(session, {})
                self.assertEqual(session.get.call_count, 1)
                self.assertEqual(session.post.call_count, 0 if phase == "get" else 1)

    def test_malformed_challenge_never_posts(self):
        for result in (response(text="<html>login</html>"), response([])):
            session = self.session()
            session.get.return_value = result
            with self.assertRaises(requests.RequestException):
                checkin.prepare_checkin(session, {})
            session.post.assert_not_called()

    def test_reflected_nonce_and_proof_do_not_enter_logs_or_result(self):
        session = self.session()
        nonce = "browser-reference-nonce"
        proof = "7d4d4eeb87b7d4e9f358ef166b3ad76d595c7ca862291d544ca76b262e2ae71d"
        session.post.return_value = response({"code": 2, "message": nonce + " " + proof, "points": nonce})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = checkin.checkin_request(session, {})
        self.assertNotIn(nonce, output.getvalue() + json.dumps(result))
        self.assertNotIn(proof, output.getvalue() + json.dumps(result))
        self.assertIsNone(result["points"])

    def test_http_response_body_cannot_leak_validation_or_cookie(self):
        session = AccountTests().session({})
        secret = "browser-reference-nonce"
        session.post.return_value = response({"message": secret + COOKIE}, status=403)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            account = checkin.checkin_account(session, COOKIE, 1)
        self.assertIn("HTTP 403", account["status"])
        self.assertNotIn(secret, output.getvalue() + json.dumps(account))
        self.assertNotIn("test-session", output.getvalue() + json.dumps(account))

    def test_official_repeat_flag_and_rejection_take_priority(self):
        for result, expected in (
            ({"code": 0, "message": "Recorded", "repeated": True}, "🔄"),
            ({"code": 0, "message": "Recorded", "reason": "turnstile", "repeated": True}, "❌"),
            ({"code": 0, "message": "Checkin! Got 1 Points", "points": 1}, "✅"),
        ):
            session = AccountTests().session(result)
            account = checkin.checkin_account(session, COOKIE, 1)
            self.assertIn(expected, account["status"])


class BrowserGuardTests(unittest.TestCase):
    def test_cloudflare_body_diagnostic_returns_only_codes_and_fixed_labels(self):
        codes, labels = turnstile_response_diagnostics(
            '{"code":110200,"nonce":"PRIVATE-TEST-NONCE","message":"Domain not authorized"}'
        )
        self.assertEqual(codes, {"110200"})
        self.assertEqual(labels, {"domain-not-authorized"})
        self.assertEqual(turnstile_response_diagnostics("PRIVATE-TEST-NONCE"), (set(), set()))

    def test_console_diagnostic_extracts_only_known_numeric_error_code(self):
        self.assertEqual(turnstile_error_code("[Cloudflare Turnstile] Error: 600010. private-data"), "600010")
        self.assertIsNone(turnstile_error_code("Cookie private-data Error: 600010"))
        self.assertIsNone(turnstile_error_code("[Cloudflare Turnstile] Cookie private-data"))

    def setUp(self):
        self.challenge = {"code": 0, "nonce": "browser-reference-nonce", "ttl": 300000,
                          "turnstile": {"sitekey": "public"}, "received_at": 1000.0}
        self.payload = {"token": "glados.cloud", "nonce": "browser-reference-nonce",
                        "proof": "7d4d4eeb87b7d4e9f358ef166b3ad76d595c7ca862291d544ca76b262e2ae71d",
                        "tsState": "ok", "turnstile": "synthetic-unit-test-token"}

    def test_official_completed_submission_is_allowed(self):
        validate_submission(self.payload, self.challenge, 1003)

    def test_official_error_and_timeout_states_are_forwarded_without_forging_a_token(self):
        for state in ("error", "timeout"):
            payload = {**self.payload, "tsState": state}
            del payload["turnstile"]
            validate_submission(payload, self.challenge, 1003)
            self.assertEqual(payload["tsState"], state)
            self.assertNotIn("turnstile", payload)

    def test_server_rejection_after_browser_submission_still_fails_the_account(self):
        session = AccountTests().session({})
        responses = list(session.get.side_effect)
        responses[1] = challenge(turnstile={"sitekey": "public"})
        session.get.side_effect = responses
        rejection = {"code": 5, "reason": "turnstile", "message": "Verification required"}
        with mock.patch("browser_checkin.browser_checkin", return_value=(rejection, [])) as browser:
            result = checkin.checkin_account(session, COOKIE, 1)
        self.assertIn("❌", result["status"])
        browser.assert_called_once()
        session.post.assert_not_called()

    def test_incomplete_or_downgraded_submission_is_blocked(self):
        for patch in ({"nonce": "other-nonce"}, {"proof": "wrong"}, {"token": "other.example"},
                      {"tsState": "off"}, {"tsState": "timeout"}, {"tsState": "unknown"}, {"turnstile": ""},
                      {"turnstile": True}, {"turnstile": {"token": "fake"}}):
            with self.subTest(field=list(patch)):
                with self.assertRaises(BrowserFlowError):
                    validate_submission({**self.payload, **patch}, self.challenge, 1003)
        with self.assertRaises(BrowserFlowError):
            validate_submission({"token": "glados.cloud"}, self.challenge, 1003)

    def test_expired_rejected_and_missing_challenges_are_blocked(self):
        for challenge_data in (None, {**self.challenge, "code": -2}, {**self.challenge, "code": False},
                               {**self.challenge, "ttl": "300000"}, {**self.challenge, "ttl": float("inf")}):
            with self.assertRaises(BrowserFlowError):
                validate_submission(self.payload, challenge_data, 1003)
        with self.assertRaises(BrowserFlowError):
            validate_submission(self.payload, self.challenge, 1290)

    def test_off_state_allowed_only_without_turnstile_requirement(self):
        validate_submission({**self.payload, "tsState": "off"},
                            {**self.challenge, "turnstile": None}, 1003)
        with self.assertRaises(BrowserFlowError):
            validate_submission(self.payload, {**self.challenge, "turnstile": None}, 1003)

    def test_cookies_remain_scoped_to_the_official_origin(self):
        cookies = browser_cookies(COOKIE, "https://glados.cloud")
        self.assertEqual({c["name"] for c in cookies}, {"gld:sess", "gld:sess.sig", "optional"})
        self.assertTrue(all(c["url"] == "https://glados.cloud" for c in cookies))
        self.assertTrue(all(c["secure"] and c["sameSite"] == "Lax" for c in cookies))
        self.assertTrue(all(c["httpOnly"] for c in cookies if c["name"].startswith("gld:")))
        self.assertFalse(next(c for c in cookies if c["name"] == "optional")["httpOnly"])
        with self.assertRaises(BrowserFlowError):
            browser_cookies("", "https://glados.cloud")


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
