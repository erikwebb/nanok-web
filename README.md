# nanok-web

The official static website for **Nanok Consulting**: [https://nanok.consulting](https://nanok.consulting)

## Hosting & Architecture

* **Hosting**: [Cloudflare Pages](https://pages.cloudflare.com/)
* **Primary URL**: [https://nanok.consulting](https://nanok.consulting)
* **Redirects**: `https://www.nanok.consulting` canonically redirects (301) to the apex domain.
* **CI/CD**: Cloudflare Pages builds and deploys updates automatically whenever commits are pushed to the `main` branch.

## Repository Structure

```text
├── index.html           # Main landing page
├── assets/
│   ├── bootstrap.bundle.min.js
│   ├── site.css
│   └── images/          # Self-contained local images and icons
├── _headers             # Cloudflare Pages security & caching rules
├── favicon.png
├── robots.txt
└── package.json         # Development scripts
```

## Local Development

Preview the site locally using Wrangler:

```bash
# Install dependencies
npm install

# Run local preview server
npm run dev
```

## Manual Deployment

While pushes to `main` deploy automatically via Git integration, you can also deploy directly from the CLI:

```bash
npm run deploy
```
