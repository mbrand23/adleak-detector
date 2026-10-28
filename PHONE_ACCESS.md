# Open AdLeak on your phone (Tailscale)

Tailscale puts your own devices on a private network. Your phone can then open AdLeak while it runs on this PC. Nobody outside your Tailscale account can reach it, and nothing is put on the public internet. The free Personal plan is enough.

AdLeak itself still listens only on `127.0.0.1`. `tailscale serve` receives the request on your private Tailscale address (with HTTPS) and passes it to AdLeak on this PC.

## One-time setup

**1. On this PC**
1. Download Tailscale for Windows from <https://tailscale.com/download/windows> and install it. It needs about 100 MB on drive C:.
2. Click the Tailscale icon in the system tray, choose **Log in**, and sign in with Google, Microsoft, GitHub or email.

**2. On your phone**
1. Install **Tailscale** from the App Store or Google Play.
2. Sign in with the **same account** as the PC.
3. Switch the Tailscale connection **on** (allow the VPN prompt).

**3. Turn on private HTTPS addresses (once per account)**
1. Open <https://login.tailscale.com/admin/dns>.
2. Check that **MagicDNS** is enabled.
3. Under **HTTPS Certificates**, click **Enable HTTPS**.

**4. Forward your Tailscale address to AdLeak (on this PC)**

Open PowerShell and run:

```bash
tailscale serve --bg 8765
```

If Tailscale prints a link asking you to enable Serve, open it, approve, and run the command again. The `--bg` setting is remembered, so you only do this once, even after restarting the PC.

## Every time you want to use it

1. Double-click **`start-with-tailscale.bat`** (not `start-windows.bat`). The window prints a line like:

   ```
   On your other Tailscale devices: https://your-pc.tail1234.ts.net/
   ```

2. On your phone, with Tailscale switched on, open that `https://...ts.net/` address. Add it to your home screen if you like.
3. Keep the PC awake and the AdLeak window open while you use it. Scans run on the PC; the phone only shows the pages.

## Showing other people

- The easiest way is to hand them your phone or laptop.
- To let someone use it from their own phone, invite them to your Tailscale network (admin console, **Users**, **Invite**). Only invite people you trust: they share your one report history and can delete reports, because AdLeak has no separate accounts yet.

## Stopping phone access

- Close the AdLeak window: the phone address stops working straight away.
- To remove the forwarding completely: `tailscale serve reset`

## Safety rules

- **Never run `tailscale funnel` for AdLeak.** Funnel publishes a service on the public internet. AdLeak isn't ready for that (see ARCHITECTURE.md and ROADMAP.md, Milestone 5).
- Every device signed in to your Tailscale account can open AdLeak. Remove old devices in the admin console under **Machines**.

## If something doesn't work

| What you see | Fix |
|---|---|
| "Unexpected Host header" | You started `start-windows.bat`. Close it and use `start-with-tailscale.bat`. |
| "Tailscale is installed but not connected" | Open Tailscale from the system tray and sign in. |
| The phone can't load the page at all | Switch Tailscale on in the phone app, check the PC is awake, and check that `tailscale serve status` lists port 8765. |
| "Cross-site requests are not allowed" when scanning | Open the exact `https://...ts.net/` address the window printed, not an IP address or `http://`. |
| You started AdLeak on another port | Run `tailscale serve --bg <that port>` to match. |
