use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::types::DetectionResult;

/// Job status enum.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// A submitted analysis job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Job {
    pub id: u64,
    pub status: JobStatus,
    pub input: String,
    pub input_type: String,
    pub context: String,
    pub deep: bool,
    pub ai: bool,
    pub sandbox: bool,
    pub created_at: String,
    pub updated_at: String,
    pub result: Option<DetectionResult>,
}

/// Shared job queue state.
pub struct JobQueue {
    next_id: AtomicU64,
    jobs: RwLock<HashMap<u64, Job>>,
    max_concurrent: usize,
    running_count: AtomicU64,
}

impl JobQueue {
    pub fn new(max_concurrent: usize) -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(1),
            jobs: RwLock::new(HashMap::new()),
            max_concurrent,
            running_count: AtomicU64::new(0),
        })
    }

    /// Submit a new job and return its ID.
    pub async fn submit(&self, input: String, input_type: String, context: String, deep: bool, ai: bool, sandbox: bool) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let now = chrono_now();
        let job = Job {
            id,
            status: JobStatus::Pending,
            input,
            input_type,
            context,
            deep,
            ai,
            sandbox,
            created_at: now.clone(),
            updated_at: now,
            result: None,
        };
        self.jobs.write().await.insert(id, job);
        id
    }

    /// Get a job by ID.
    pub async fn get(&self, id: u64) -> Option<Job> {
        self.jobs.read().await.get(&id).cloned()
    }

    /// Cancel a job by ID.
    pub async fn cancel(&self, id: u64) -> Option<Job> {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(&id) {
            if job.status == JobStatus::Pending || job.status == JobStatus::Running {
                job.status = JobStatus::Cancelled;
                job.updated_at = chrono_now();
            }
        }
        jobs.get(&id).cloned()
    }

    /// Remove a completed/failed/cancelled job.
    pub async fn remove(&self, id: u64) -> bool {
        self.jobs.write().await.remove(&id).is_some()
    }

    /// Try to dispatch the next pending job. Returns true if a job was started.
    async fn dispatch_one(self: Arc<Self>) -> bool {
        let running = self.running_count.load(Ordering::SeqCst) as usize;
        if running >= self.max_concurrent {
            return false;
        }

        let next_id = {
            let jobs = self.jobs.read().await;
            jobs.iter()
                .find(|(_, j)| j.status == JobStatus::Pending)
                .map(|(id, _)| *id)
        };

        let id = match next_id {
            Some(id) => id,
            None => return false,
        };

        // Mark as running
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&id) {
                if job.status != JobStatus::Pending {
                    return false;
                }
                job.status = JobStatus::Running;
                job.updated_at = chrono_now();
            }
        }

        self.running_count.fetch_add(1, Ordering::SeqCst);

        let job_snapshot = {
            let jobs = self.jobs.read().await;
            jobs.get(&id).cloned()
        };

        if let Some(job_data) = job_snapshot {
            let queue = self.clone();
            let queue_clone = queue.clone();
            tokio::spawn(async move {
                queue_clone.run_job(job_data).await;
                queue.running_count.fetch_sub(1, Ordering::SeqCst);
            });
            true
        } else {
            false
        }
    }

    /// Start a background worker that polls for pending jobs.
    pub fn start_worker(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = self.clone().dispatch_one().await;
            }
        });
    }

    async fn run_job(self: Arc<Self>, job: Job) {
        let id = job.id;
        let result = crate::api::routes::run_analysis(
            &job.input,
            &job.input_type,
            &job.context,
            job.deep,
            job.ai,
            job.sandbox,
        ).await;

        let mut jobs = self.jobs.write().await;
        if let Some(entry) = jobs.get_mut(&id) {
            match result {
                Ok(detection) => {
                    entry.status = JobStatus::Completed;
                    entry.result = Some(detection);
                }
                Err(e) => {
                    entry.status = JobStatus::Failed(format!("{:?}", e));
                }
            }
            entry.updated_at = chrono_now();
        }
    }
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    format!("{}.{:03}", secs, millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_submit_and_get() {
        let queue = JobQueue::new(4);
        let id = queue.submit(
            "test".to_string(),
            "string".to_string(),
            "forensics".to_string(),
            false,
            false,
            false,
        ).await;
        let job = queue.get(id).await.unwrap();
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.input, "test");
    }

    #[tokio::test]
    async fn test_cancel_pending() {
        let queue = JobQueue::new(4);
        let id = queue.submit("data".to_string(), "string".to_string(), "forensics".to_string(), false, false, false).await;
        let cancelled = queue.cancel(id).await.unwrap();
        assert_eq!(cancelled.status, JobStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_remove() {
        let queue = JobQueue::new(4);
        let id = queue.submit("data".to_string(), "string".to_string(), "forensics".to_string(), false, false, false).await;
        assert!(queue.remove(id).await);
        assert!(queue.get(id).await.is_none());
    }
}
