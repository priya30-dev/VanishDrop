"""Browser end-to-end tests. Start two devices first (see README), then:  python tests/test_web.py"""
import asyncio, os, json, sys, ssl, urllib.request
from playwright.async_api import async_playwright

A = "https://localhost:5001"          # owner of device A
B = "http://localhost:5002"           # owner of device B
LAN = os.environ.get("VD_LAN", "192.0.2.2")
VIS = f"https://{LAN}:5001"           # a visitor on the Wi-Fi reaching device A
OUT = os.environ.get("VD_SHOTS", "/home/claude/shots2")
CHROME = os.environ.get("VD_CHROME", "/usr/bin/google-chrome")
results = []

def check(label, cond):
    results.append((label, bool(cond))); print(("PASS " if cond else "FAIL ") + label)

def raw(url, method="GET", headers=None, data=None):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, context=ctx) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

async def share(page, path=None, note=None, downloads="1", pw=None):
    await page.goto(A + ("/notes" if note else "/"))
    if note: await page.fill("#note-text", note)
    else: await page.set_input_files("#file-input", path)
    await page.select_option("#downloads", downloads)
    if pw: await page.check("#use-password"); await page.fill("#password", pw)
    await page.click("#share-btn"); await page.wait_for_selector("#result:not([hidden])", timeout=30000)
    return await page.input_value("#share-link")

async def main():
    secret = os.urandom(400000); open("/tmp/Aadhaar_card.pdf", "wb").write(b"%PDF" + secret)
    open("/tmp/marksheet.pdf", "wb").write(os.urandom(90000)); open("/tmp/photos.zip", "wb").write(os.urandom(1500000))
    async with async_playwright() as p:
        br = await p.chromium.launch(executable_path=CHROME, args=["--no-sandbox", "--no-proxy-server"])
        own = await br.new_context(viewport={"width": 1360, "height": 900}, ignore_https_errors=True, accept_downloads=True, bypass_csp=True)
        vis = await br.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, ignore_https_errors=True, accept_downloads=True, bypass_csp=True)
        errs = []
        def watch(pg): pg.on("pageerror", lambda e: errs.append(str(e))); pg.on("console", lambda m: errs.append(m.text) if m.type == "error" and "403" not in m.text and "410" not in m.text and "404" not in m.text else None)
        page = await own.new_page(); watch(page)

        # 1 · plain link
        await page.goto(A + "/"); await page.screenshot(path=f"{OUT}/01_share.png", full_page=True)
        link = await share(page, "/tmp/Aadhaar_card.pdf")
        check("link uses the network address, not localhost", link.startswith(VIS) and "#" in link)
        await page.screenshot(path=f"{OUT}/02_link_ready.png")
        v = await vis.new_page(); watch(v)
        await v.goto(link); await v.wait_for_selector("#dl-ready:not([hidden])")
        await v.wait_for_function("document.getElementById('dl-btn').disabled === false")
        check("visitor sees the decrypted file name", await v.text_content("#file-name") == "Aadhaar_card.pdf")
        check("key is removed from the address bar", "#" not in v.url)
        await v.screenshot(path=f"{OUT}/03_download_phone.png")
        async with v.expect_download() as d: await v.click("#dl-btn")
        f = await d.value; got = open(await f.path(), "rb").read()
        check("downloaded file matches the original exactly", got == b"%PDF" + secret)
        await v.wait_for_selector("#dl-done:not([hidden])", timeout=10000)
        await v.goto(link); await v.wait_for_selector("#dl-gone:not([hidden])")
        check("link is dead after the last download", "vanished" in (await v.text_content("#gone-title")))
        await v.screenshot(path=f"{OUT}/04_gone_phone.png")

        # 2 · password link, wrong then right
        plink = await share(page, "/tmp/marksheet.pdf", downloads="3", pw="hostel-123")
        check("password link has no key in it", "#" not in plink)
        await v.goto(plink); await v.wait_for_selector("#pw-form:not([hidden])")
        await v.fill("#dl-password", "wrong-pass"); await v.click("#unlock-btn")
        await v.wait_for_selector("#dl-error:not([hidden])", timeout=20000)
        check("wrong password shows tries left", "4 tries left" in await v.text_content("#dl-error"))
        await v.screenshot(path=f"{OUT}/05_wrong_password.png")
        await v.fill("#dl-password", "hostel-123"); await v.click("#unlock-btn")
        await v.wait_for_function("document.getElementById('dl-btn').disabled === false", timeout=20000)
        async with v.expect_download() as d: await v.click("#dl-btn")
        check("right password downloads", (await d.value).suggested_filename == "marksheet.pdf")

        # 3 · lockout after 5 wrong passwords
        llink = await share(page, "/tmp/marksheet.pdf", pw="correct-horse")
        lid = llink.rsplit("/", 1)[1]
        for i in range(5):
            await v.goto(llink); await v.wait_for_selector("#pw-form:not([hidden]), #dl-gone:not([hidden])")
            if await v.is_visible("#dl-gone"): break
            await v.fill("#dl-password", f"guess{i}xx"); await v.click("#unlock-btn")
            await v.wait_for_selector("#dl-error:not([hidden]), #dl-gone:not([hidden])", timeout=20000)
        await v.goto(llink); await v.wait_for_selector("#dl-gone:not([hidden])")
        check("5 wrong passwords lock and destroy the file", "Locked" in await v.text_content("#gone-title"))
        check("locked file's bytes are wiped from disk", not os.path.exists(f"/tmp/vdA/links/{lid}.bin"))

        # 4 · secret note
        nlink = await share(page, note="Wi-Fi: Hostel_5G\nPassword: tulip-42-river")
        await v.goto(nlink); await v.wait_for_function("document.getElementById('dl-btn').disabled === false")
        await v.click("#dl-btn"); await v.wait_for_selector("#dl-note:not([hidden])")
        check("note text decrypts correctly", await v.text_content("#note-text") == "Wi-Fi: Hostel_5G\nPassword: tulip-42-river")
        await v.screenshot(path=f"{OUT}/06_note_phone.png")
        await v.goto(nlink); await v.wait_for_selector("#dl-gone:not([hidden])")
        check("note burns after one read", True)

        # 5 · attacks on links
        alink = await share(page, "/tmp/marksheet.pdf")
        aid = alink.split("/d/")[1].split("#")[0]
        s, _ = raw(f"{VIS}/api/links/{aid}/blob")
        check("blob without the key is refused", s == 403)
        s, body = raw(f"{VIS}/api/links/{aid}/open", "POST", {"X-VD": "1", "X-VD-Auth": "A" * 43})
        check("guessing the key is refused and counted", s == 403 and json.loads(body)["attempts_left"] == 3)
        s, body = raw(f"{VIS}/api/links/{aid}")
        info = json.loads(body)
        check("public info leaks no name or check data", "enc_meta" not in info and "check" not in info)

        # 6 · visitors can't reach owner features
        s, body = raw(f"{VIS}/")
        check("visitor gets the read-only page at /", s == 403 and b"Sharing and settings only work" in body)
        for path in ["/api/nearby/state", "/api/events", "/api/server-view"]:
            s, _ = raw(VIS + path)
            check(f"visitor blocked from {path}", s == 403)
        s, _ = raw(VIS + "/api/links", "POST", {"X-VD": "1"}, b"")
        check("visitor can't create links on someone else's device", s == 403)

        # 7 · CSRF and DNS rebinding
        s, _ = raw(A + "/api/nearby/settings", "POST", {"Content-Type": "application/json"}, b'{"allow_plain":true}')
        check("POST without the X-VD header is refused (CSRF)", s == 400)
        s, _ = raw(A + "/api/nearby/settings", "POST", {"X-VD": "1", "Origin": "https://evil.example", "Content-Type": "application/json"}, b'{"allow_plain":true}')
        check("POST from another website is refused (CSRF)", s == 403)
        s, _ = raw(A + "/api/whoami", headers={"Host": "evil.example:5001"})
        check("unknown Host header is refused (DNS rebinding)", s == 400)
        s, _ = raw(A + "/d/../../etc/passwd")
        check("path tricks in URLs don't reach files", s in (404, 400))

        # 8 · security headers
        req = await page.request.get(A + "/")
        csp = req.headers.get("content-security-policy", "")
        check("strict Content-Security-Policy is set", "script-src 'self'" in csp and "frame-ancestors 'none'" in csp)

        # 9 · upload request
        await page.goto(A + "/requests"); await page.fill("#req-title", "Aadhaar copies for the scholarship form")
        await page.click("#req-btn"); await page.wait_for_selector("#req-result:not([hidden])", timeout=20000)
        rlink = await page.input_value("#req-link"); code = await page.text_content("#req-code")
        await page.screenshot(path=f"{OUT}/07_request_created.png")
        await v.goto(rlink); await v.wait_for_selector("#up-form:not([hidden])")
        check("uploader sees the same check code", await v.text_content("#up-code") == code)
        await v.fill("#up-name", "Rahul Verma"); await v.set_input_files("#up-file", "/tmp/photos.zip")
        await v.screenshot(path=f"{OUT}/08_request_upload_phone.png")
        await v.click("#up-btn"); await v.wait_for_selector("#up-done:not([hidden])", timeout=30000)
        check("upload to request succeeds", True)
        rid = rlink.rsplit("/", 1)[1]
        s, _ = raw(f"{VIS}/api/requests/{rid}/uploads/x/blob")
        check("visitors can't download other people's uploads", s == 403)
        await page.goto(A + "/requests"); await page.wait_for_selector("text=From Rahul Verma", timeout=20000)
        await page.screenshot(path=f"{OUT}/09_requests_owner.png", full_page=True)
        async with page.expect_download() as d: await page.click("button:text-is('Save and wipe')")
        check("owner decrypts the upload byte-for-byte", open(await (await d.value).path(), "rb").read() == open("/tmp/photos.zip", "rb").read())
        await page.wait_for_timeout(800)
        check("upload wiped from server after saving", not os.listdir("/tmp/vdA/uploads"))

        # 10 · nearby: pair and send from A to B through both UIs
        pb = await own.new_page(); watch(pb)
        await pb.goto(B + "/nearby")
        await page.goto(A + "/nearby"); await page.wait_for_selector("#peers .item", timeout=15000)
        check("device A sees device B on the network", "Priya's laptop" in await page.text_content("#peers"))
        await page.click("#peers button:text-is('Pair')")
        await pb.wait_for_selector("#pending .decision", timeout=15000)
        code_b = await pb.text_content("#pending .code")
        await page.wait_for_selector("text=Safety code", timeout=10000)
        check("both screens show the same safety code", code_b in await page.text_content("#jobs"))
        await pb.screenshot(path=f"{OUT}/10_pair_request.png", full_page=True)
        await pb.click("#pending button:text-is('Accept')")
        await page.wait_for_selector("#friends .item", timeout=15000)
        check("pairing makes them friends", "Priya's laptop" in await page.text_content("#friends"))
        await page.click("#peers button:text-is('Send a file')")
        await page.set_input_files("#send-file", "/tmp/photos.zip"); await page.click("#send-go")
        await page.wait_for_selector("text=Delivered to Priya's laptop", timeout=30000)
        await pb.wait_for_selector("#inbox .item", timeout=15000)
        check("friend's file arrives without asking", "photos.zip" in await pb.text_content("#inbox"))
        await page.screenshot(path=f"{OUT}/11_nearby_sender.png", full_page=True)
        await pb.screenshot(path=f"{OUT}/12_nearby_receiver.png", full_page=True)
        async with pb.expect_download() as d: await pb.click("#inbox a:text-is('Save')")
        check("received file matches", open(await (await d.value).path(), "rb").read() == open("/tmp/photos.zip", "rb").read())
        await page.wait_for_timeout(2500)

        # 10b · secure chat through the UI, with a scam link
        await page.goto(A + "/chat"); await page.wait_for_selector("#chat-open:not([hidden])", timeout=10000)
        await page.fill("#msg", "Hi Priya! Update your KYC here: http://sbi-kyc-update.xyz/login"); await page.click("#send")
        await page.wait_for_selector(".msg.out .msg-meta:has-text('Delivered')", timeout=15000)
        check("chat message is delivered", True)
        await pb.goto(B + "/chat"); await pb.wait_for_selector(".msg.in", timeout=10000)
        check("friend receives the chat message", "Hi Priya!" in await pb.text_content("#messages"))
        check("scam link in chat is flagged", "Suspicious link" in await pb.text_content("#messages") and "SBI" in await pb.text_content("#messages"))
        await pb.screenshot(path=f"{OUT}/17_chat.png", full_page=True)
        s, _ = raw(VIS + "/api/chat/state")
        check("visitors can't read chats", s == 403)

        # 10c · traffic monitor
        await page.goto(A + "/monitor"); await page.wait_for_selector("#rows tr", timeout=10000)
        await page.wait_for_timeout(1500)
        await page.click("button.filter[data-f='udp']"); mon_udp = await page.text_content("#rows")
        await page.click("button.filter[data-f='tcp']"); mon_tcp = await page.text_content("#rows")
        check("monitor shows UDP beacons and VD1 frames", "beacon" in mon_udp and ("HELLO" in mon_tcp or "CHUNK" in mon_tcp or "REQUEST" in mon_tcp))
        await page.click("button.filter[data-f='all']")
        await page.click("#rows tr"); await page.wait_for_selector("#d-body:not([hidden])")
        check("monitor explains a packet", len(await page.text_content("#d-explain")) > 40)
        await page.screenshot(path=f"{OUT}/18_monitor.png", full_page=True)
        s, _ = raw(VIS + "/api/monitor")
        check("visitors can't see the monitor", s == 403)

        # 10d · photo privacy cleaner on an upload request (visitor side)
        if os.path.exists("/tmp/hostel_photo.jpg"):
            await page.goto(A + "/requests"); await page.fill("#req-title", "Event photos"); await page.click("#req-btn")
            await page.wait_for_selector("#req-result:not([hidden])"); plink = await page.input_value("#req-link")
            await v.goto(plink); await v.wait_for_selector("#up-form:not([hidden])")
            await v.fill("#up-name", "Rahul"); await v.set_input_files("#up-file", "/tmp/hostel_photo.jpg")
            await v.wait_for_selector("#up-privacy:not([hidden])")
            check("uploader is warned the photo reveals location", "where it was taken" in await v.text_content("#up-privacy"))
            await v.screenshot(path=f"{OUT}/19_photo_privacy_phone.png", full_page=True)
            await v.click("#up-btn"); await v.wait_for_selector("#up-done:not([hidden])", timeout=20000)
            await page.goto(A + "/requests"); await page.wait_for_selector("text=From Rahul", timeout=15000)
            async with page.expect_download() as d: await page.click("button:text-is('Save and wipe')")
            got = open(await (await d.value).path(), "rb").read()
            check("received photo has no GPS location", b"GPS" not in got and b"Samsung" not in got)

        # 11 · network check (module 1)
        await page.goto(A + "/network"); await page.click("button[data-tool='ipconfig']"); await page.click("#run")
        await page.wait_for_selector("#out-card:not([hidden])", timeout=60000)
        check("network check runs ipconfig / ip addr", len(await page.text_content("#output")) > 20)
        await page.click("button[data-tool='ping']"); await page.fill("#target", "127.0.0.1"); await page.click("#run")
        await page.wait_for_function("document.getElementById('out-title').textContent.includes('ping')", timeout=60000)
        await page.screenshot(path=f"{OUT}/16_network.png", full_page=True)
        check("network check pings", "127.0.0.1" in await page.text_content("#output"))
        s, body = raw(A + "/api/netcheck", "POST", {"X-VD": "1", "Content-Type": "application/json"}, b'{"tool":"ping","target":"8.8.8.8; rm -rf /"}')
        check("command injection in the target is refused", s == 400)
        s, body = raw(A + "/api/netcheck", "POST", {"X-VD": "1", "Content-Type": "application/json"}, b'{"tool":"ping","target":"-f"}')
        check("option injection in the target is refused", s == 400)
        s, _ = raw(VIS + "/api/netcheck", "POST", {"X-VD": "1", "Content-Type": "application/json"}, b'{"tool":"ipconfig"}')
        check("visitors can't run network commands", s == 403)

        # 12 · files, alerts, server view
        await page.goto(A + "/files"); await page.wait_for_timeout(1500)
        await page.screenshot(path=f"{OUT}/13_my_files.png", full_page=True)
        ev = await page.text_content("#events")
        check("activity shows downloads and delivery alert", "Aadhaar_card.pdf was downloaded" in ev and "saved photos.zip" in ev)
        await share(page, "/tmp/photos.zip")
        await page.goto(A + "/server-view"); await page.wait_for_selector(".hexdump")
        await page.screenshot(path=f"{OUT}/14_server_view.png", full_page=True)
        check("server view shows only scrambled bytes", "photos" not in await page.text_content("#vault"))
        await page.goto(A + "/"); await page.set_viewport_size({"width": 390, "height": 844})
        await page.screenshot(path=f"{OUT}/15_share_mobile.png", full_page=True)

        check("no JavaScript errors: " + "; ".join(errs[:3]), not errs)
        await br.close()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
