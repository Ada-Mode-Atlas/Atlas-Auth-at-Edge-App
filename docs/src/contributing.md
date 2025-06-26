# Atlas Application | Contribution

This application uses the Atlas platform.

The `atlas_sdk` python library consists of reusable methods, classes, templates & cloud resources for integration into Atlas applications and projects.

## Prerequisites

You'll need the following prerequisites:

- `Python` version within **>=3.12**
- [**`uv`**](https://docs.astral.sh/uv/getting-started/installation/) virtual environment tool and pip eco-system replacement
- **`git`**
- **`make`** (please note that make is not available on Windows - you should be able to copy commands out of the make file and run them directly)
- **`npm`** (note this is only need for the `.vitepress` static site generator and can be skipped if documentation is not required for this application)

To get npm for windows, install the nvm-windows tool [here](https://github.com/coreybutler/nvm-windows) by downloading the .exe from the latest release.

Then you can install & select a version of node like this:
```bash
nvm install 22.1.0
nvm use 22.1.0 # node version 22.1.0 used here
```

You can list currently installed versions:
```bash
nvm list
```

## [1] Installation and setup


```bash
# Clone the repo and cd into the repo directory
git clone https://github.com/Ada-Mode-Atlas/... # pass repository name here
cd ... # pass repository name here
```

The `sdk` is hosted on a private repository within the Ada Mode Atlas organisation, to install the SDK you will need a personal access token. Instructions to create one can be found [here](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens). To install only basic read-only requirements to the [SDK](https://github.com/Ada-Mode-Atlas/Atlas-SDK) repository are required. If an application owner, it is recommended that an env var be created named `ATLAS_SDK_TOKEN` containing a PAT for installing the SDK which is used within the Makefile for the build process.

Now you can create the environment
```bash

# Install UV
# pip is used here, for other options:
# https://docs.astral.sh/uv/getting-started/installation/
pip install uv

# Install atlas-sdk, pre-commit & all dependencies in a virtual environmment
make install
```

## [2] Check out a new branch and make changes

Create a new branch for your changes.

```bash
# Checkout a new branch and make your changes
git checkout -b {label}/new-branch
# Build features, fix bugs, write documentation, optimise ... work
```

## [3] Run tests and linting

Run tests and linting locally:

```bash
# Run automated code formatting and linting
make format

# Run tests, typecheck, format/linting assessment, spell check, docstring review
make ci
```

Current static-code checking includes the following:
* All public modules, packages, methods, functions and classes have type annotations & correspondng docstrings in google format for arguments and returns
* `Ruff` linting and formatting
* `Pyright` type checking
* Spell checking with `Codespell`
* `Pydoclint` checking of docstring content


## [4] Committing changes


::: info
If you've added requirements to the application you can add them to the *pyproject.toml* like this:
```bash
uv add {NEW_REQUIREMENT}
```
You can specify if its optional or add it to a group like this:
```bash
uv add {NEW_REQUIREMENT} --optional
uv add {NEW_REQUIREMENT} --group dev
```
Current groups are `dev`, `docs`, `linting`, `typechecking`, `build`. These groups are not
packaged in the application but are needed for developing it.
:::


Write useful, modular and self-sufficient commit messages with labels:

```bash
git add {}
git commit -m 'fix: incorrect distance calculation'

git add {}
git commit -m 'refactor: aggregation approach in IoT application'

git add {}
git commit -m 'feat: new performance metrics available in regression pipeline'

```

The list of available commits tags can be found at *./gitlint*. At the time of writing they are: [`breaking`,`fix`,`change`,`refactor`,`upgrade`,`docs`,`bump`,`test`,`feat`,`perf`,`chore`,`ignore`]

This syntax is enforced within the pre-commit workflow.

Any raised issues relating to linting/formatting/docstring/type-check/spell-check will prevent the commit, some issues will be fixed automatically such that a follow up commit can resolve the error:
```bash
git add '{pre-commit hook edited files}'
git commit -m '{prior-commit}'
```
Other cases such as type violations may be corrected via manual corrections.

If not required or if this workflow doesn't fit nicely with a preferred local workflow, the pre-commit hooks can be skipped like this:
```bash
git commit -m 'label: message' --no-verify
```

### [5] Pushing changes

Push your branch to GitHub, and create a draft pull request against the dev branch.

Please follow the pull request template and fill in as much information as possible. Link to any relevant issues and include a description of your changes.

If your changes originate from a issue or discussion be sure to tag them here so that they close on completion (WIP).

When your pull request is ready for review, convert it from draft to ready and assign a reviewer.

If your changes effect certain files that have a specified 'owner' such as key configeration files or frontend assets then your pull-request may automatically assign a reviewer.