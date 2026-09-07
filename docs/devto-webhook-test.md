---
devto: true
title: Testing the GitHub to dev.to Publisher
tags:
  - github
  - devtools
  - typescript
published: false
canonical_url: https://devto-publisher.darkedges.com/
description: A disposable unpublished article used to verify GitHub webhook synchronization.
---

# Testing the GitHub to dev.to Publisher

This disposable article verifies that a Markdown push in this repository reaches the GitHub App publisher.

The publisher should create an unpublished article on dev.to, then commit the returned `devto_id` into this file. A second edit should update the same article instead of creating another one.

Webhook test update.
