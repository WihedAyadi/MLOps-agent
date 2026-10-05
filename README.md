# MLOps Verification Agent

A FastAPI web application that checks Python and machine-learning projects for dependency, security, structure, and deployment-readiness issues. It can optionally use OpenRouter for AI-generated project insights and fix plans.

## Requirements

- Python 3.13
- Docker Desktop (optional, for containerized usage)
- An OpenRouter API key only when AI analysis is enabled

## Local Setup

Create and activate a virtual environment, then install the pinned dependencies:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirement.txt
```

Start the application:

```powershell
python main.py
```

Open the web interface at <http://localhost:8000>.

The health endpoint is available at <http://localhost:8000/health>.

## API Usage

The `POST /check` endpoint accepts a project directory visible to the running application:

```powershell
$body = @{
    directory_path = "C:\projects\my-ml-project"
    checks = @("all")
    use_ai = $false
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri http://localhost:8000/check `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

Supported check values are:

- `dependencies`
- `security`
- `structure`
- `deployment`
- `all`

When AI analysis is enabled, provide `openrouter_api_key` in the request or configure the key through the runtime environment. Never commit API keys to the repository.

## Docker

The Dockerfile contains two stages:

- `base`: Python 3.13 and the pinned dependencies
- `dev`: the application source and templates, running as a non-root user

Build the reusable base image:

```powershell
docker build --target base -t mlops-verification-base:3.13 .
```

Build the application image:

```powershell
docker build --target dev -t mlops-verification-dev:3.13 .
```

Run the application:

```powershell
docker run --rm -p 8000:8000 mlops-verification-dev:3.13
```

To scan a project directory from inside the container, mount it and use the mounted path in the request:

```powershell
docker run --rm -p 8000:8000 `
    -v "C:\projects\my-ml-project:/workspace:ro" `
    mlops-verification-dev:3.13
```

Then send `"directory_path": "/workspace"` to `/check`. The read-only mount prevents the verifier from modifying the scanned project.

## CI/CD

The workflow is defined in `.github/workflows/CI-CD.yml`. Pull requests and pushes to `main` run these checks:

1. Install the pinned dependencies.
2. Compile the Python sources.
3. Verify that the FastAPI application imports.
4. Audit dependencies with `pip-audit`.
5. Build the Docker image.
6. Start the container and verify `/health`.

A successful push to `main` also publishes the image to GitHub Container Registry with a `latest` tag and a commit-SHA tag. The workflow generates SBOM and provenance metadata and uses package write permissions only in the publish job.

## Security Notes

- Keep API keys in environment variables or a secret manager. Do not place them in source files, README examples, Docker images, or Git history.
- Do not commit private keys, `.env` files, virtual environments, or generated secrets.
- Prefer read-only volume mounts when scanning projects with Docker.
- Review dependency-audit results before releasing an image.
- The application accepts filesystem paths from requests, so deploy it only in a trusted network and consider adding authentication before exposing it publicly.

## Project Layout

```text
main.py                    FastAPI application
agent/main.py              MLOps verification logic
templates/index.html       Web interface
requirement.txt            Pinned Python dependencies
dockerfile                 Base and dev Docker stages
.github/workflows/CI-CD.yml CI/CD workflow
```
