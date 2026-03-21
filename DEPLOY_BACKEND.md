Backend deployment for shared data

This version is meant for a real Python web service, not GitHub Pages.

What it supports
- shared customers for all users
- shared trainings for all users
- shared price list for all users
- shared uploaded files, as long as deployment storage is persistent

Recommended deploy
1. Push the full project to GitHub:
   - `index.html`
   - `logo.png`
   - `main.py`
2. Create a new Web Service on Render
3. Connect the GitHub repository
4. Use:
   - Runtime: `Python`
   - Build command: leave empty
   - Start command: `py main.py` on Windows is local only, so on Render use `python main.py`
5. Render will provide the `PORT` environment variable automatically

Important
- `main.py` now binds to `0.0.0.0` and reads `PORT`, so it is ready for deployment
- shared app data is stored in `app_state.json`
- uploaded files are stored in `uploads/`

For production hosting
- use a host with persistent disk or persistent volume
- otherwise uploaded files and shared data can be lost on redeploy/restart

If you want full production reliability
- next step should be moving `app_state.json` to a real database
- that is especially recommended for multiple simultaneous users
