package github

import (
	"context"
	"strconv"

	"github.com/grantlinehq/grantline/internal/model"
)

func (c *collection) smoke(ctx context.Context, base, repoID, workflowID string, s SmokeCheck, revisions []model.GitHubRevision) (model.GitHubSmokeResult, string) {
	var run struct {
		ID         int64  `json:"id"`
		Attempt    int    `json:"run_attempt"`
		WorkflowID int64  `json:"workflow_id"`
		HeadSHA    string `json:"head_sha"`
		Event      string `json:"event"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
		HeadRepository struct {
			ID int64 `json:"id"`
		} `json:"head_repository"`
	}
	empty := model.GitHubSmokeResult{}
	endpoint := base + "/actions/runs/" + s.RunID + "/attempts/" + strconv.Itoa(s.Attempt)
	if _, code := c.get(ctx, endpoint, &run); code != "" {
		return empty, code
	}
	if strconv.FormatInt(run.ID, 10) != s.RunID || run.Attempt != s.Attempt || strconv.FormatInt(run.WorkflowID, 10) != workflowID || strconv.FormatInt(run.Repository.ID, 10) != repoID || strconv.FormatInt(run.HeadRepository.ID, 10) != repoID || !model.GitHubSHA.MatchString(run.HeadSHA) || run.Status != "completed" || !model.GitHubConclusion(run.Conclusion) {
		return empty, "unresolved_smoke_run"
	}
	if run.Event != "push" && run.Event != "workflow_dispatch" && run.Event != "pull_request" {
		return empty, "unsupported_smoke_event"
	}
	pinned := false
	for _, r := range revisions {
		if r.CommitSHA == run.HeadSHA {
			pinned = true
		}
	}
	if !pinned {
		return empty, "smoke_commit_not_collected"
	}
	var job struct {
		ID         int64  `json:"id"`
		RunID      int64  `json:"run_id"`
		Attempt    int    `json:"run_attempt"`
		HeadSHA    string `json:"head_sha"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Steps      *[]struct {
			Number     int    `json:"number"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		} `json:"steps"`
	}
	if _, code := c.get(ctx, base+"/actions/jobs/"+s.JobID, &job); code != "" {
		return empty, code
	}
	if strconv.FormatInt(job.ID, 10) != s.JobID || strconv.FormatInt(job.RunID, 10) != s.RunID || job.Attempt != s.Attempt || job.HeadSHA != run.HeadSHA || job.Status != "completed" || !model.GitHubConclusion(job.Conclusion) || job.Steps == nil || len(*job.Steps) > 1000 {
		return empty, "unresolved_smoke_job"
	}
	conclusion := ""
	seen := map[int]bool{}
	for _, step := range *job.Steps {
		if step.Number < 1 || seen[step.Number] {
			return empty, "invalid_smoke_steps"
		}
		seen[step.Number] = true
		if step.Number == s.LoginStepNumber && step.Status == "completed" && model.GitHubConclusion(step.Conclusion) {
			conclusion = step.Conclusion
		}
	}
	if conclusion == "" {
		return empty, "unresolved_smoke_step"
	}
	c.observed("Actions selected run and job GET")
	return model.GitHubSmokeResult{RunID: s.RunID, Attempt: s.Attempt, JobID: s.JobID, LoginStepNumber: s.LoginStepNumber, CommitSHA: run.HeadSHA, Event: run.Event, RunConclusion: run.Conclusion, JobConclusion: job.Conclusion, StepConclusion: conclusion}, ""
}
