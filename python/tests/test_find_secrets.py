"""Run with: uv run python -m unittest discover -s tests -v"""

from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import find_secrets as scanner


TOKEN = "q7B2m9K4v6R8z1N3t5W0yXaC"
HEX = "a3f9c120d8e647b5a0c2f91e83d467b5"


def cli(*args, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with (
        patch.object(sys, "argv", ["find_secrets.py", *args]),
        patch.object(sys, "stdin", io.StringIO(stdin)),
        redirect_stdout(out),
        redirect_stderr(err),
    ):
        scanner.main()
    return out.getvalue(), err.getvalue()


class SecretScannerTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(scanner.entropy(""), 0)
        self.assertEqual(scanner.entropy("aaaa"), 0)
        self.assertEqual(scanner.entropy("abcd"), 2)

    def test_assignments_hex_base64_and_repeated_tokens(self):
        values = [TOKEN, HEX, TOKEN + "+/==", TOKEN]
        text = "\n".join(f'API_KEY={value}' for value in values)
        findings = list(scanner.find_secrets(text))
        self.assertEqual([text[f.start:f.end] for f in findings], values)
        self.assertEqual(findings[1].reason, "high-entropy hex")

    def test_prefix_bypasses_entropy_and_minimum_length(self):
        token = "ghp_" + "a" * 16
        result = list(scanner.find_secrets(token, min_length=100, threshold=8))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].reason, "token prefix")

    def test_low_entropy_and_prose_do_not_match(self):
        text = "An ordinary sentence about configuration. " + "a" * 80
        self.assertEqual(list(scanner.find_secrets(text)), [])
        self.assertEqual(list(scanner.find_secrets(TOKEN, threshold=6)), [])
        self.assertEqual(list(scanner.find_secrets(HEX, hex_threshold=4.1)), [])

    def test_context_is_exactly_fifteen_source_characters(self):
        before = "a longer prefix: αβγ\n"
        after = "\tδεζ and a longer suffix"
        text = before + TOKEN + after
        finding = list(scanner.find_secrets(text))[0]
        expected = (
            "…" + scanner.visible(before[-15:]) + "[[" + TOKEN + "]]"
            + scanner.visible(after[:15]) + "…"
        )
        self.assertEqual(scanner.render_finding(text, finding, 15, False), expected)
        self.assertEqual(
            scanner.render_finding(TOKEN, list(scanner.find_secrets(TOKEN))[0], 15, False),
            "[[" + TOKEN + "]]",
        )
        self.assertEqual(
            scanner.render_finding(text, finding, 0, False), "…[[" + TOKEN + "]]…"
        )

    def test_stdin_positions_and_color(self):
        out, err = cli("-", "--color", "never", stdin=f"first\nkey={TOKEN}\n{TOKEN}")
        self.assertIn("2:5  high entropy", out)
        self.assertIn("3:1  high entropy", out)
        self.assertEqual(out.count("[[" + TOKEN + "]]"), 2)
        self.assertNotIn("\033", out)
        self.assertIn("2 possible secret(s)", err)
        colored, _ = cli("-", "--color", "always", stdin=TOKEN)
        self.assertIn("\033[1;31m[[" + TOKEN + "]]\033[0m", colored)

    def test_controls_are_escaped(self):
        out, _ = cli("-", stdin="\033[2J" + TOKEN + "\r\n\u202e")
        self.assertNotIn("\033", out)
        self.assertNotIn("\u202e", out)
        self.assertIn(r"\x1b", out)

    def test_file_and_empty_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.txt"
            path.write_text(f'token="{TOKEN}"', encoding="utf-8")
            out, _ = cli(str(path))
            self.assertIn("[[" + TOKEN + "]]", out)
        out, err = cli("-", stdin="")
        self.assertEqual(out, "")
        self.assertIn("0 possible secret(s)", err)

    def test_http_response_and_error(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/missing":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=iso-8859-1")
                self.end_headers()
                self.wfile.write(("café " + TOKEN).encode("iso-8859-1"))

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                out, _ = cli(url)
                self.assertIn("café [[" + TOKEN + "]]", out)
                with self.assertRaises(SystemExit) as ex:
                    cli(url + "/missing")
                self.assertEqual(ex.exception.code, 2)
            finally:
                server.shutdown()
                thread.join()

    def test_invalid_options_and_missing_file(self):
        for args in (
            ("-", "--context", "-1"),
            ("-", "--min-length", "0"),
            ("-", "--threshold", "nan"),
            ("-", "--hex-threshold", "-1"),
        ):
            with self.subTest(args=args), self.assertRaises(SystemExit) as ex:
                cli(*args)
            self.assertEqual(ex.exception.code, 2)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit) as ex:
                cli(str(Path(directory) / "missing.txt"))
            self.assertEqual(ex.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
