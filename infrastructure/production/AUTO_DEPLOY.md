# Automatic production deployment

Push to `main` runs `.github/workflows/ci.yml`. Frontend/backend checks, builds, Linux agent tests and Windows agent tests must pass before production deployment. Pull requests never deploy. Superseded commits are skipped.

The deployment job streams the checked commit to the production server over a pinned SSH connection. The dedicated key can only invoke `/usr/local/sbin/cybershield-deploy-gateway`; shell access and forwarding are disabled. Repository secrets: `PRODUCTION_HOST`, `PRODUCTION_SSH_KEY`, `PRODUCTION_KNOWN_HOSTS`.

The gateway builds frontend and backend together, creates a verified PostgreSQL dump, runs pending migrations, switches the application image and checks local/public health. A failed application switch restores the previous image. Migrations are **not** automatically reversed: ship additive, backward-compatible migrations; destructive changes require a separately planned maintenance operation. A failed migration prevents the application switch.

Production environment values remain on the server in `/opt/cybershield360/private/production.env`. Existing compose settings are preserved. Backups are under `/opt/cybershield360/private/backups`; releases under `/opt/cybershield360/releases`; the deployed SHA is in `/opt/cybershield360/deployment/current-revision`. Monitor disk usage and retain backups according to your retention policy. Host agents are not automatically upgraded by this workflow.

The root-owned gateway is installed separately from application releases. Changes to this script require an administrator to review and install the updated copy at `/usr/local/sbin/cybershield-deploy-gateway`. To roll back application code, revert the relevant commit and push to `main`; database recovery must be assessed separately to avoid losing new user data.
