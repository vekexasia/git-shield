from privacy_prepush.opf import parse_opf_json


def test_parse_opf_json_with_summary_prefix():
    output = '''summary: output_mode=typed spans=1
{
  "detected_spans": [
    {"label": "private_email", "text": "real.person@gmail.com", "start": 1, "end": 22}
  ]
}
'''
    findings = parse_opf_json(output)
    assert len(findings) == 1
    assert findings[0].label == "private_email"
    assert findings[0].text == "real.person@gmail.com"
