from curlguard.curl_args import parse_curl_args


def test_supported_installer_request_is_rewritten_for_temporary_output():
    invocation = parse_curl_args(
        ["-fsSLo", "installer.sh", "https://example.com/install.sh"]
    )

    assert invocation.intercept is True
    assert invocation.output == "installer.sh"
    assert invocation.download_args == ("-fsSL", "https://example.com/install.sh")


def test_proxy_url_is_not_mistaken_for_a_second_download():
    invocation = parse_curl_args(
        ["--proxy", "http://127.0.0.1:8080", "https://example.com/install.sh"]
    )

    assert invocation.intercept is True
    assert invocation.urls == ("https://example.com/install.sh",)


def test_request_bodies_and_head_requests_pass_through():
    assert parse_curl_args(["--data=value", "https://example.com"]).intercept is False
    assert parse_curl_args(["-IsS", "https://example.com"]).intercept is False


def test_unknown_options_and_multiple_urls_pass_through_unchanged():
    unknown = ["--write-out", "%{json}", "https://example.com"]
    multiple = ["https://one.example", "https://two.example"]

    assert parse_curl_args(unknown).download_args == tuple(unknown)
    assert parse_curl_args(multiple).download_args == tuple(multiple)


def test_conflicting_output_modes_pass_through():
    args = ["-o", "one", "-O", "https://example.com/file"]

    assert parse_curl_args(args).intercept is False
