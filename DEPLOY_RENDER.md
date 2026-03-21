Render deploy:

1. Push the repo to GitHub.
2. In Render click `New +` -> `Blueprint`.
3. Select this repo.
4. Render will read [render.yaml](C:/Users/akinn/PycharmProjects/PythonProject/render.yaml).
5. Add a persistent disk in Render and mount it at `/var/data`.
6. Deploy.

Important:

- The app now reads `PORT` automatically on Render.
- Persistent files are stored in `APP_DATA_DIR`, set to `/var/data` in `render.yaml`.
- Without a persistent disk, `app_state.json`, `auth.json`, and uploads can be lost on restart.
