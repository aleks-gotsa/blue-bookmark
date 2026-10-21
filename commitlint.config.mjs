// Conventional Commits rules for this repository.
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['feat', 'fix', 'test', 'refactor', 'docs', 'chore', 'perf', 'ci']],
    'scope-enum': [2, 'always', ['detector', 'eval', 'workflow', 'demo']],
    'subject-max-length': [2, 'always', 72],
    'subject-full-stop': [2, 'never', '.'],
  },
};
