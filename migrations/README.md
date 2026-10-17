# 🗄️ Legacy SQL Migrations

These are the numbered SQL migrations the server used to apply itself, kept for
reference only.

## 📕 Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [📦 What Replaced Them](#-what-replaced-them)
- [⬆️ Upgrading An Existing Instance](#-upgrading-an-existing-instance)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## 📦 What Replaced Them

Nothing reads these files any more. Prisma Migrate owns the schema, and
`prisma/migrations/0_baseline` is the whole of what they built, produced by
introspecting a database at their final state.

## ⬆️ Upgrading An Existing Instance

A deployment that already ran all 29 of these is adopted rather than rebuilt:
`runMigrations` in `src/db.js` marks the baseline applied once it sees the
complete set in `schema_migrations`, and refuses to start on a partial one. See
the [deploy guide](../docs/deploy.md#-upgrading-from-the-sql-migration-releases).
