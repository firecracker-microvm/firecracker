# Contributions Welcome

Firecracker is running serverless workloads at scale within AWS, but it's still
day 1 on the journey guided by our [mission](CHARTER.md). There's a lot more to
build and we welcome all contributions.

There's a lot to contribute to in Firecracker. We've opened issues for all the
features we want to build and improvements we want to make. Good first issues
are labeled accordingly. We're also keen to hearing about your use cases and how
we can support them, your ideas, and your feedback for what's already here.

If you're just looking for quick feedback for an idea or proposal, open an
[issue](https://github.com/firecracker-microvm/firecracker/issues) or chat with
us on the [Firecracker Slack workgroup](https://firecracker-microvm.slack.com).

Follow the [contribution workflow](#contribution-workflow) for submitting your
changes to the Firecracker codebase. If you want to receive high-level but still
commit-based feedback for a contribution, follow the
[request for comments](#request-for-comments) steps instead.

## Contribution Workflow

Firecracker uses the “fork-and-pull” development model. Follow these steps if
you want to merge your changes to Firecracker:

1. Within your fork of
   [Firecracker](https://github.com/firecracker-microvm/firecracker), create a
   branch for your contribution. Use a meaningful name.
1. Create your contribution, meeting all
   [contribution quality standards](#contribution-quality-standards)
1. [Create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/)
   against the master branch of the Firecracker repository.
1. Add two reviewers to your pull request (a maintainer will do that for you if
   you're new). Work with your reviewers to address any comments and obtain a
   minimum of 2 approvals, at least one of which must be provided by
   [a maintainer](MAINTAINERS.md).
   To update your pull request amend existing commits whenever applicable and
   then push the new changes to your pull request branch.
1. Once the pull request is approved, one of the maintainers will merge it.

## Request for Comments

If you just want to receive feedback for a contribution proposal, open an “RFC”
(“Request for Comments”) pull request:

1. On your fork of
   [Firecracker](https://github.com/firecracker-microvm/firecracker), create a
   branch for the contribution you want feedback on. Use a meaningful name.
1. Create your proposal based on the existing codebase.
1. [Create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/)
   against the master branch of the Firecracker repository. Prefix your pull
   request name with `[RFC]`.
1. Discuss your proposal with the community on the pull request page (or on any
   other channel). Add the conclusion(s) of this discussion to the pull request
   page.

## Contribution Quality Standards

Most quality and style standards are enforced automatically during integration
testing. Your contribution needs to meet the following standards:

- Separate each **logical change** into its own commit.
- Each commit must pass all unit & code style tests, and the full pull request
  must pass all integration tests. See [tests/README.md](tests/README.md) for
  information on how to run tests.
- Unit test coverage must _increase_ the overall project code coverage.
- Include integration tests for any new functionality in your pull request.
- Document all your public functions.
- Add a descriptive message for each commit. Follow
  [commit message best practices](https://github.com/erlang/otp/wiki/writing-good-commit-messages).
- Document your pull requests. Include the reasoning behind each change, and
  the testing done.
- Acknowledge Firecracker's [Apache 2.0 license](LICENSE) and certify that no
  part of your contribution contravenes this license by signing off on all your
  commits with `git -s`. Ensure that every file in your pull request has a
  header referring to the repository license file.
