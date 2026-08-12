# Issue tracker: GitHub

Issues and PRDs for this repo live in `nisavid/fork-ops` GitHub issues. Use the
`gh` CLI for all operations and bind every command to that repository.

## Conventions

- **Create an issue**: `gh issue create --repo nisavid/fork-ops --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --repo nisavid/fork-ops --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --repo nisavid/fork-ops --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --repo nisavid/fork-ops --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --repo nisavid/fork-ops --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --repo nisavid/fork-ops --comment "..."`

Before a tracker mutation, verify
`gh repo view nisavid/fork-ops --json nameWithOwner --jq .nameWithOwner` returns
exactly `nisavid/fork-ops`. Never infer the tracker target from Git remotes, a
GitHub CLI default repository, or the current working directory.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --repo nisavid/fork-ops --comments`.
