import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
import tool

ROOT = Path(__file__).parent

def fixture(name="good"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())

class CLITests(unittest.TestCase):
    def run_tool(self, raw):
        return subprocess.run([sys.executable, str(ROOT / "tool.py")], input=raw, capture_output=True, text=True)

    def test_cli_fixture_exit_codes(self):
        for name, code in [("good", 0), ("bad", 1)]:
            run = subprocess.run([sys.executable, str(ROOT / "tool.py"), "--input", str(ROOT / "examples" / (name + ".json"))], capture_output=True, text=True)
            self.assertEqual(run.returncode, code, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["ok"], code == 0)
            self.assertEqual(run.stderr, "")

    def test_cli_argument_errors_are_json_and_redacted(self):
        secret = "PRIVATE_ARGUMENT_MARKER"
        for arguments in [("--unknown", secret), ("--input",),
                          ("--pretty=" + secret,), (secret,)]:
            run = subprocess.run([sys.executable, str(ROOT / "tool.py"), *arguments],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stderr, "")
            self.assertNotIn(secret, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "invalid_input")

    def test_cli_help_remains_text_and_success(self):
        run = subprocess.run([sys.executable, str(ROOT / "tool.py"), "--help"],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stderr, "")
        self.assertIn("--input", run.stdout)

    def test_large_json_integer_is_safe_error(self):
        run=self.run_tool('{"number":'+'9'*5000+'}')
        self.assertEqual(run.returncode,2)
        self.assertEqual(run.stderr,'')
        self.assertEqual(json.loads(run.stdout)['error']['code'],'invalid_input')

    def test_nonregular_input_file(self):
        run=subprocess.run([sys.executable,str(ROOT/'tool.py'),'--input',str(ROOT)],capture_output=True,text=True)
        self.assertEqual(run.returncode,2)
        self.assertEqual(run.stderr,'')

    def test_bad_json(self):
        for raw in ['{', '{"x":1,"x":2}', '[]', '{"x":NaN}', '"' + 'x' * (tool.MAX_BYTES + 1) + '"']:
            run = self.run_tool(raw)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "invalid_input")

    def test_unknown_field_and_boolean_number(self):
        obj = fixture(); obj["unrecognized"] = 1
        with self.assertRaises(tool.InputError): tool.audit(obj)

    def test_output_is_deterministic(self):
        raw=json.dumps(fixture())
        self.assertEqual(self.run_tool(raw).stdout, self.run_tool(raw).stdout)

import base64
class MultipartTests(unittest.TestCase):
    def test_valid_two_parts(self):
        out=tool.audit(fixture()); self.assertTrue(out['ok']); self.assertEqual(out['observed_part_delimiters'],2)
    def test_collision_prefix(self):
        d=fixture(); d['parts']=['safe\r\n--fixture-2024extra']
        self.assertIn('payload_boundary_prefix_collision',{x['code'] for x in tool.audit(d)['findings']})
    def test_non_line_boundary_is_not_collision(self):
        d=fixture(); d['parts']=['text --fixture-2024 inside']
        self.assertTrue(tool.audit(d)['ok'])
    def test_missing_close(self):
        d=fixture(); d['closing']=False
        self.assertFalse(tool.audit(d)['ok'])
    def test_lf_framing(self):
        d=fixture(); d['newline']='lf'
        self.assertFalse(tool.audit(d)['ok'])
    def test_inspect_matches_synthesis(self):
        wire=tool.build_fixture(b'b',[b'one',b'two'])
        out=tool.audit({'mode':'inspect','boundary':'b','wire_base64':base64.b64encode(wire).decode()})
        self.assertTrue(out['ok']); self.assertEqual(out['observed_part_delimiters'],2)
    def test_bare_cr_delimiter_endings_are_rejected(self):
        wires = [b'--b\r\r\nx\r\n--b--\r\n',
                 b'--b\r\n\r\nx\r\n--b--\r',
                 b'--b\r\n\r\nx\r\n--b--\r\r\n',
                 b'--b\r\n\r\nx\r--b--\r\n', b'--b']
        for wire in wires:
            data = {'mode': 'inspect', 'boundary': 'b',
                    'wire_base64': base64.b64encode(wire).decode()}
            self.assertFalse(tool.audit(data)['ok'], repr(wire))
            run = subprocess.run(
                [sys.executable, str(ROOT / 'tool.py')], input=json.dumps(data),
                capture_output=True, text=True)
            self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
            self.assertEqual(run.stderr, '')

    def test_binary_bare_cr_is_not_a_payload_line_boundary(self):
        for payload in [b'left\rright', b'left\r--b--\r\nright',
                        b'\x00\r\xff', b'--not-b\r', b'left\v--b--\fright']:
            wire = b'--b\r\n\r\n' + payload + b'\r\n--b--\r\n'
            out = tool.audit({'mode': 'inspect', 'boundary': 'b',
                              'wire_base64': base64.b64encode(wire).decode()})
            self.assertTrue(out['ok'], (repr(payload), out))
            self.assertEqual(out['observed_part_delimiters'], 1)
            self.assertEqual(out['closing_delimiters'], 1)

    def test_transport_padding_and_exact_final_crlf_controls(self):
        for close in [b'--b--', b'--b--\r\n', b'--b-- \t', b'--b-- \t\r\n']:
            wire = b'--b \t\r\n\r\nx\r\n' + close
            self.assertEqual(tool.inspect_wire(b'b', wire)[0], [], repr(wire))
        for wire in [b'--b\n\r\nx\r\n--b--\r\n',
                     b'--b\r\n\r\nx\n--b--\r\n',
                     b'--b\r\n\r\nx\r\n--b--\n']:
            self.assertTrue(tool.inspect_wire(b'b', wire)[0], repr(wire))

    def test_final_crlf_optional(self):
        wire=tool.build_fixture(b'b',[b'one'])[:-2]
        self.assertTrue(tool.audit({'mode':'inspect','boundary':'b','wire_base64':base64.b64encode(wire).decode()})['ok'])
    def test_empty_headers_allowed(self):
        wire=b'--b\r\n\r\ntext\r\n--b--\r\n'
        self.assertTrue(tool.inspect_wire(b'b',wire)[0]==[])
    def test_unsupported_preamble_epilogue(self):
        for wire in [b'prefix\r\n'+tool.build_fixture(b'b',[b'x']),tool.build_fixture(b'b',[b'x'])+b'epilogue']:
            self.assertTrue(tool.inspect_wire(b'b',wire)[0])
    def test_no_payload_in_output(self):
        d=fixture(); d['parts']=['PRIVATE_PAYLOAD']
        self.assertNotIn('PRIVATE_PAYLOAD',json.dumps(tool.audit(d)))
    def test_invalid_inputs(self):
        for key,value in [('boundary','x '*36),('boundary','bad\r\n'),('boundary','b '),('parts',[]),('parts',['x'*8193]),('closing',1),('newline','CR')]:
            d=fixture(); d[key]=value
            with self.assertRaises(tool.InputError): tool.audit(d)
        with self.assertRaises(tool.InputError): tool.audit({'mode':'inspect','boundary':'b','wire_base64':'!!!!'})
if __name__=='__main__': unittest.main()
