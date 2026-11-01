# Projects and environments

A project is the unit of ownership and encryption: each has its own data key, its own members and roles, and its own audit log. Usually one project maps to one application or service.

Inside a project, every secret lives in exactly one environment and one folder. A new project gets `dev`, `staging` and `prod`. You can rename, reorder and add environments in the project's settings, or pass your own list at creation:

```sh
sekret projects create billing --name Billing --environment dev --environment prod
```

An environment can only be deleted once it holds no secrets, because deleting it also deletes every version and snapshot inside it. Delete or move the secrets first.

## Folders

Folders are paths such as `/` or `/payments/stripe`, made of letters, digits, `_`, `-` and `.`. They let one project hold several services' settings and give access rules something to match on. Writing a secret to a folder that does not exist creates it, along with any missing parents.

Most commands take `--path`, and the read commands take `--recursive` to include subfolders. When a recursive read finds the same key in two folders, the CLI stops rather than picking one, because the result would otherwise depend on ordering.

## Project settings

Each project and environment has an ID, such as `storefront` or `prod`, used by the CLI and in URLs. It is chosen at creation and cannot change; the display name can.

Project settings hold the name, description and logo, the environments, the members and roles (see [Access control](access-control.md)), the default generation and rotation policy (see [Generation and rotation](rotation.md)) and the danger zone, where the project can be deleted. Deleting a project removes all its secrets, versions, snapshots, roles and memberships at once.

Logos can be PNG, JPEG, GIF, WebP or SVG, up to 512 KiB and 4096 pixels on a side. The server decodes the upload, renders SVGs, and stores a PNG of at most 512 pixels, so the original file is never served back. SVGs with filters, with very many or deeply nested masks, clip paths and patterns, or with dashed lines cut into a huge number of dashes, are refused.
