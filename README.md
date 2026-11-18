# Concert Tracker
Self-hosted (Flask + SQLite) concert log. MIT-style: do what you like with it.

    mkdir -p data && chown 1000 data   # container runs as uid 1000
    cp .env.example .env               # then add your SETLISTFM_API_KEY
    docker compose up -d --build   # then open http://localhost:8000

- First account you register becomes admin. Admin creates invite links under **Invites**.
- Add shows by searching setlist.fm, importing your setlist.fm "attended" list, or manually.
- Open a concert to upload photos/videos, or paste an Instagram link: the bundled [cobalt](https://github.com/imputnet/cobalt) container resolves it and the files are saved to that concert. Only public posts work out of the box; see the cookies note in docker-compose.yml. Cobalt is AGPL-3.0 and runs as a separate container, so this app stays independent.
- Everyone logged in can browse each other's concerts; only owners edit. Put it behind HTTPS (Caddy/Traefik) before exposing it.
- Data: `./data/app.db` + `./data/media/`. Back up that folder.

## GitHub
Pushing to `main` builds and publishes `ghcr.io/<you>/<repo>` via `.github/workflows/docker.yml`. To use it, replace `build: .` in docker-compose.yml with `image: ghcr.io/<you>/<repo>:main`.
