#!/usr/bin/env bats
# Point 9: Git push-to-deploy — dm_setup_git_deploy / dm_get_git_remote

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"
  GIT_REPOS_DIR="${TEST_DIR}/git-repos"
  mkdir -p "$GIT_REPOS_DIR"

  # Mock git init --bare (create the directory structure)
  git() {
    if [[ "$1" == "init" && "$2" == "--bare" ]]; then
      local repo_dir="$3"
      mkdir -p "${repo_dir}/hooks"
      return 0
    fi
    command git "$@"
  }
  export -f git

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_setup_git_deploy ---

@test "setup_git_deploy: creates bare git repo directory" {
  dm_setup_git_deploy "example.com"
  [ -d "${GIT_REPOS_DIR}/example.com.git" ]
}

@test "setup_git_deploy: creates hooks directory in bare repo" {
  dm_setup_git_deploy "example.com"
  [ -d "${GIT_REPOS_DIR}/example.com.git/hooks" ]
}

@test "setup_git_deploy: creates post-receive hook" {
  dm_setup_git_deploy "example.com"
  [ -f "${GIT_REPOS_DIR}/example.com.git/hooks/post-receive" ]
}

@test "setup_git_deploy: post-receive hook contains GIT_WORK_TREE" {
  dm_setup_git_deploy "example.com"
  local hook="${GIT_REPOS_DIR}/example.com.git/hooks/post-receive"
  grep -q "GIT_WORK_TREE" "$hook"
  grep -q "${WEB_ROOT}/example.com/www/public" "$hook"
}

@test "setup_git_deploy: post-receive hook is executable" {
  dm_setup_git_deploy "example.com"
  local hook="${GIT_REPOS_DIR}/example.com.git/hooks/post-receive"
  local perms
  perms=$(stat -c %a "$hook")
  [[ "$perms" == *"7"* ]] || [[ "$perms" == *"5"* ]]
}

@test "setup_git_deploy: post-receive hook contains git checkout" {
  dm_setup_git_deploy "example.com"
  local hook="${GIT_REPOS_DIR}/example.com.git/hooks/post-receive"
  grep -q "checkout" "$hook"
}

@test "setup_git_deploy: idempotent (second run does not fail)" {
  dm_setup_git_deploy "example.com"
  dm_setup_git_deploy "example.com"
  [ -f "${GIT_REPOS_DIR}/example.com.git/hooks/post-receive" ]
}

@test "setup_git_deploy: works with subdomain" {
  dm_setup_git_deploy "app.example.com"
  [ -d "${GIT_REPOS_DIR}/app.example.com.git" ]
  [ -f "${GIT_REPOS_DIR}/app.example.com.git/hooks/post-receive" ]
  grep -q "${WEB_ROOT}/app.example.com/www/public" \
    "${GIT_REPOS_DIR}/app.example.com.git/hooks/post-receive"
}

# --- dm_get_git_remote ---

@test "get_git_remote: returns correct remote URL format" {
  dm_setup_git_deploy "example.com"
  run dm_get_git_remote "example.com"
  [ "$status" -eq 0 ]
  [[ "$output" == *"${HOSTNAME_FQDN}"* ]]
  [[ "$output" == *"example.com.git"* ]]
}

@test "get_git_remote: includes SSH user and path" {
  dm_setup_git_deploy "example.com"
  run dm_get_git_remote "example.com"
  [ "$status" -eq 0 ]
  # Expected format: ssh://user@host[:port]/path or user@host:path
  [[ "$output" == *"${GIT_REPOS_DIR}/example.com.git"* ]] || \
    [[ "$output" == *"example.com.git"* ]]
}
