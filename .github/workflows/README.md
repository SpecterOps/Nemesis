# GitHub Actions for Nemesis

This directory contains GitHub Action workflows for automating tasks related to the Nemesis project.

## Docker Build and Publish Workflow

The `docker-build.yml` workflow automatically builds and publishes Docker images for all Nemesis services to the GitHub Container Registry (ghcr.io).

### Workflow Trigger

The workflow runs on:
- Push to the `main` branch (when specific paths are modified)
- Pull requests targeting the `main` branch (when specific paths are modified)
- Manual triggers via the GitHub Actions UI (workflow_dispatch)

### What It Does

1. **Base Images Build Job**:
   - Builds the Python base images (dev and prod) and the InspectAssembly image
   - Pushes them to the GitHub Container Registry
   - Passes the image tags to the next job

2. **Service Images Build Job**:
   - Uses a matrix strategy to build all service images in parallel
   - Builds both development and production targets for each service
   - References the base images built in the first job
   - Pushes all images to the GitHub Container Registry

### Image Tags

Each image is tagged with:
- The short SHA of the commit
- The branch name
- `latest` (only for the default branch)

Development images are additionally tagged with `-dev` suffix.

### How to Use the Published Images

#### In docker compose

To use these images in your docker compose file, update your service definitions:

```yaml
services:
  web-api:
    image: ghcr.io/your-org/nemesis/web-api:latest
    # For development images
    # image: ghcr.io/your-org/nemesis/web-api:latest-dev
```

#### In a Production Environment

For production deployments, reference specific versions by commit SHA for stability:

```yaml
services:
  web-api:
    image: ghcr.io/your-org/nemesis/web-api:sha-abc123
```

### Required Repository Secrets

For this workflow to function properly, ensure:

1. Your repository has appropriate permissions to write packages
2. GitHub Actions has permission to create and push container images

No additional secrets are needed as the workflow uses the built-in `GITHUB_TOKEN`.

### Customization

To customize the workflow:
- Change the registry by modifying the `REGISTRY` env variable
- Update the image naming prefix in the `IMAGE_PREFIX` env variable
- Add or remove services in the matrix configuration


## Documentation Build and Publish Workflow

The `docs.yml` workflow automatically builds and publishes the Nemesis project documentation to GitHub Pages whenever documentation files are updated.

### Workflow Trigger

The workflow runs on:
- Push to the `main` branch when specific documentation-related files are modified:
  - Files in the `docs/` directory
  - The `mkdocs.yml` configuration file
  - The workflow file itself (`.github/workflows/docs.yml`)

### Environment and Permissions

The workflow runs in the `github-pages` environment with the following permissions:
- `pages: write`: Allows publishing to GitHub Pages
- `id-token: write`: Enables secure deployment
- `contents: read`: Provides access to repository content

### How Documentation is Generated

The workflow uses MkDocs, a popular Python-based documentation generator:
1. Documentation source files are written in Markdown
2. The `mkdocs.yml` file configures the structure and appearance
3. MkDocs processes these files to create a static website
4. The generated site is deployed to GitHub Pages

### Accessing the Published Documentation

After a successful workflow run, the documentation is available at:
`https://<organization-name>.github.io/<repository-name>/`


## Code Vulnerability Scan Workflow

The `vuln-scan.yml` workflow automatically scans the Nemesis codebase for security vulnerabilities using Aqua Security's Trivy scanner.

### Workflow Trigger

The workflow runs on:
- Push to the `main` branch
- Pull requests targeting the `main` branch (excluding changes to documentation files)
