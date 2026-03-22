//! Scan Scheduler
//!
//! Provides cron-like scheduling for periodic scans.

use chrono::{DateTime, Datelike, Utc, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::scanners::Target;

/// Priority for scan jobs
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScanPriority {
    /// Low priority - can be delayed
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority - should run soon
    High = 2,
    /// Critical priority - run immediately
    Critical = 3,
}

impl Default for ScanPriority {
    fn default() -> Self {
        ScanPriority::Normal
    }
}

/// A scheduled scan
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduledScan {
    /// Unique ID for this scheduled scan
    pub id: Uuid,
    /// Target to scan
    pub target: Target,
    /// When this scan was scheduled
    pub scheduled_at: DateTime<Utc>,
    /// Priority of the scan
    pub priority: ScanPriority,
    /// What triggered this scan (if any)
    pub trigger: Option<super::ScanTrigger>,
}

/// Schedule definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Schedule {
    /// Unique schedule identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of the schedule
    pub description: Option<String>,
    /// Cron-like expression
    pub cron_expression: String,
    /// Targets to scan
    pub targets: Vec<Target>,
    /// Scanner profile to use
    pub profile: String,
    /// Whether this schedule is enabled
    pub enabled: bool,
    /// Priority for scans from this schedule
    pub priority: ScanPriority,
    /// Last time this schedule triggered
    pub last_run: Option<DateTime<Utc>>,
    /// Next scheduled run time
    pub next_run: Option<DateTime<Utc>>,
}

impl Schedule {
    /// Create a new schedule
    pub fn new(id: String, name: String, cron_expression: String) -> Self {
        Self {
            id,
            name,
            description: None,
            cron_expression,
            targets: Vec::new(),
            profile: "default".to_string(),
            enabled: true,
            priority: ScanPriority::Normal,
            last_run: None,
            next_run: None,
        }
    }

    /// Add a target to this schedule
    pub fn with_target(mut self, target: Target) -> Self {
        self.targets.push(target);
        self
    }

    /// Set the scanner profile
    pub fn with_profile(mut self, profile: String) -> Self {
        self.profile = profile;
        self
    }

    /// Set the priority
    pub fn with_priority(mut self, priority: ScanPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Check if this schedule is due to run
    pub fn is_due(&self) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(next) = self.next_run {
            return Utc::now() >= next;
        }

        false
    }
}

/// Scheduler for periodic scans
pub struct Scheduler {
    /// Registered schedules
    schedules: HashMap<String, Schedule>,
    /// Parsed cron expressions
    cron_parsers: HashMap<String, CronExpression>,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(initial_schedules: Vec<Schedule>) -> Self {
        let mut scheduler = Self {
            schedules: HashMap::new(),
            cron_parsers: HashMap::new(),
        };

        for schedule in initial_schedules {
            scheduler.add_schedule(schedule);
        }

        scheduler
    }

    /// Add a schedule
    pub fn add_schedule(&mut self, schedule: Schedule) {
        // Parse the cron expression
        if let Ok(cron) = CronExpression::parse(&schedule.cron_expression) {
            self.cron_parsers.insert(schedule.id.clone(), cron);
        }

        // Calculate next run time
        let mut schedule = schedule;
        if let Some(cron) = self.cron_parsers.get(&schedule.id) {
            schedule.next_run = Some(cron.next_after(Utc::now()));
        }

        self.schedules.insert(schedule.id.clone(), schedule);
    }

    /// Remove a schedule
    pub fn remove_schedule(&mut self, id: &str) -> Option<Schedule> {
        self.cron_parsers.remove(id);
        self.schedules.remove(id)
    }

    /// Get a schedule by ID
    pub fn get_schedule(&self, id: &str) -> Option<&Schedule> {
        self.schedules.get(id)
    }

    /// Get all schedules
    pub fn get_all_schedules(&self) -> Vec<&Schedule> {
        self.schedules.values().collect()
    }

    /// Get all enabled schedules
    pub fn get_enabled_schedules(&self) -> Vec<&Schedule> {
        self.schedules
            .values()
            .filter(|s| s.enabled)
            .collect()
    }

    /// Get scans that are due to run
    pub fn get_due_scans(&mut self) -> Vec<ScheduledScan> {
        let now = Utc::now();
        let mut due_scans = Vec::new();

        for schedule in self.schedules.values_mut() {
            if schedule.is_due() {
                // Mark as run
                schedule.last_run = Some(now);

                // Calculate next run
                if let Some(cron) = self.cron_parsers.get(&schedule.id) {
                    schedule.next_run = Some(cron.next_after(now));
                }

                // Create scheduled scans for each target
                for target in &schedule.targets {
                    let scan = ScheduledScan {
                        id: Uuid::new_v4(),
                        target: target.clone(),
                        scheduled_at: now,
                        priority: schedule.priority,
                        trigger: Some(super::ScanTrigger::Scheduled(schedule.name.clone())),
                    };

                    due_scans.push(scan);
                }
            }
        }

        due_scans
    }

    /// Update next run times for all schedules
    pub fn update_next_runs(&mut self) {
        let now = Utc::now();

        for (id, schedule) in &mut self.schedules {
            if !schedule.enabled {
                continue;
            }

            if let Some(cron) = self.cron_parsers.get(id) {
                // If next run is in the past or not set, calculate a new one
                if schedule.next_run.map_or(true, |next| next <= now) {
                    schedule.next_run = Some(cron.next_after(now));
                }
            }
        }
    }

    /// Get schedules for a specific target
    pub fn get_schedules_for_target(&self, target: &Target) -> Vec<&Schedule> {
        self.schedules
            .values()
            .filter(|s| s.targets.contains(target))
            .collect()
    }
}

/// Parsed cron expression
#[derive(Clone, Debug)]
pub struct CronExpression {
    minutes: Vec<u32>,
    hours: Vec<u32>,
    days_of_month: Vec<u32>,
    months: Vec<u32>,
    days_of_week: Vec<u32>,
}

impl CronExpression {
    /// Parse a cron expression (5 fields: minute hour day month weekday)
    ///
    /// Supports:
    /// - *: any value
    /// - */n: every n
    /// - n: specific value
    /// - n,m: specific values
    /// - n-m: range
    pub fn parse(expression: &str) -> Result<Self, String> {
        let parts: Vec<&str> = expression.split_whitespace().collect();

        if parts.len() != 5 {
            return Err(format!(
                "Invalid cron expression: expected 5 fields, got {}",
                parts.len()
            ));
        }

        let minutes = Self::parse_field(parts[0], 0, 59)?;
        let hours = Self::parse_field(parts[1], 0, 23)?;
        let days_of_month = Self::parse_field(parts[2], 1, 31)?;
        let months = Self::parse_field(parts[3], 1, 12)?;
        let days_of_week = Self::parse_field(parts[4], 0, 6)?;

        Ok(Self {
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
        })
    }

    fn parse_field(field: &str, min: u32, max: u32) -> Result<Vec<u32>, String> {
        let mut values = Vec::new();

        for part in field.split(',') {
            if part == "*" {
                for v in min..=max {
                    values.push(v);
                }
            } else if let Some(rest) = part.strip_prefix("*/") {
                let step = rest.parse::<u32>()
                    .map_err(|_| format!("Invalid step value: {}", rest))?;

                for v in (min..=max).step_by(step as usize) {
                    values.push(v);
                }
            } else if part.contains('-') {
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(format!("Invalid range: {}", part));
                }

                let start = range_parts[0].parse::<u32>()
                    .map_err(|_| format!("Invalid range start: {}", range_parts[0]))?;
                let end = range_parts[1].parse::<u32>()
                    .map_err(|_| format!("Invalid range end: {}", range_parts[1]))?;

                if start < min || end > max {
                    return Err(format!("Range out of bounds: {}", part));
                }

                for v in start..=end {
                    values.push(v);
                }
            } else {
                let value = part.parse::<u32>()
                    .map_err(|_| format!("Invalid value: {}", part))?;

                if value < min || value > max {
                    return Err(format!("Value out of bounds: {}", part));
                }

                values.push(value);
            }
        }

        values.sort();
        values.dedup();

        Ok(values)
    }

    /// Get the minutes field
    pub fn minutes(&self) -> &[u32] {
        &self.minutes
    }

    /// Get the hours field
    pub fn hours(&self) -> &[u32] {
        &self.hours
    }

    /// Get the days of month field
    pub fn days_of_month(&self) -> &[u32] {
        &self.days_of_month
    }

    /// Get the months field
    pub fn months(&self) -> &[u32] {
        &self.months
    }

    /// Get the days of week field
    pub fn days_of_week(&self) -> &[u32] {
        &self.days_of_week
    }

    /// Get the next time this cron expression should run
    pub fn next_after(&self, after: DateTime<Utc>) -> DateTime<Utc> {
        let mut next = after + chrono::Duration::seconds(60);

        // Simple implementation - find next matching time
        // This could be optimized significantly
        loop {
            if self.matches(&next) {
                return next;
            }
            next = next + chrono::Duration::seconds(60);

            // Safety limit
            if next > after + chrono::Duration::days(365 * 4) {
                return after; // Should never happen with valid cron
            }
        }
    }

    /// Check if a given time matches this cron expression
    fn matches(&self, time: &DateTime<Utc>) -> bool {
        self.minutes.contains(&time.minute())
            && self.hours.contains(&time.hour())
            && self.days_of_month.contains(&time.day())
            && self.months.contains(&(time.month() as u32))
            && self.days_of_week.contains(&time.weekday().num_days_from_sunday())
    }
}

/// Common cron expressions
impl CronExpression {
    /// Every minute
    pub fn every_minute() -> &'static str {
        "* * * * *"
    }

    /// Every hour
    pub fn every_hour() -> &'static str {
        "0 * * * *"
    }

    /// Every day at midnight
    pub fn daily_midnight() -> &'static str {
        "0 0 * * *"
    }

    /// Every day at 6 AM
    pub fn daily_6am() -> &'static str {
        "0 6 * * *"
    }

    /// Every Monday at 9 AM
    pub fn weekly_monday_9am() -> &'static str {
        "0 9 * * 1"
    }

    /// Every Friday at 5 PM
    pub fn weekly_friday_5pm() -> &'static str {
        "0 17 * * 5"
    }

    /// On the first of every month at midnight
    pub fn monthly_first() -> &'static str {
        "0 0 1 * *"
    }

    /// Every 5 minutes
    pub fn every_5_minutes() -> &'static str {
        "*/5 * * * *"
    }

    /// Every 15 minutes
    pub fn every_15_minutes() -> &'static str {
        "*/15 * * * *"
    }

    /// Every 6 hours
    pub fn every_6_hours() -> &'static str {
        "0 */6 * * *"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_parse_every_minute() {
        let cron = CronExpression::parse("* * * * *").unwrap();
        assert_eq!(cron.minutes.len(), 60);
        assert_eq!(cron.hours.len(), 24);
    }

    #[test]
    fn test_cron_parse_specific_hour() {
        let cron = CronExpression::parse("0 9 * * *").unwrap();
        assert_eq!(cron.minutes, vec![0]);
        assert_eq!(cron.hours, vec![9]);
    }

    #[test]
    fn test_cron_parse_range() {
        let cron = CronExpression::parse("0 9-17 * * *").unwrap();
        assert_eq!(cron.minutes, vec![0]);
        assert_eq!(cron.hours, (9..=17).collect::<Vec<_>>());
    }

    #[test]
    fn test_cron_parse_list() {
        let cron = CronExpression::parse("0 9,12,17 * * *").unwrap();
        assert_eq!(cron.minutes, vec![0]);
        assert_eq!(cron.hours, vec![9, 12, 17]);
    }

    #[test]
    fn test_cron_parse_interval() {
        let cron = CronExpression::parse("*/15 * * * *").unwrap();
        assert_eq!(cron.minutes, vec![0, 15, 30, 45]);
    }

    #[test]
    fn test_cron_matches() {
        let cron = CronExpression::parse("0 9 * * 1").unwrap();

        // Monday 9:00 AM
        let time = DateTime::parse_from_rfc3339("2024-01-01T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // Jan 1, 2024 is a Monday
        assert!(cron.matches(&time));
    }

    #[test]
    fn test_schedule_creation() {
        let schedule = Schedule::new(
            "test-schedule".to_string(),
            "Test Schedule".to_string(),
            "0 9 * * *".to_string(),
        )
        .with_target(Target::Url("http://example.com".to_string()))
        .with_priority(ScanPriority::High);

        assert_eq!(schedule.id, "test-schedule");
        assert_eq!(schedule.targets.len(), 1);
        assert_eq!(schedule.priority, ScanPriority::High);
    }

    #[test]
    fn test_scan_priority_ordering() {
        assert!(ScanPriority::Critical > ScanPriority::High);
        assert!(ScanPriority::High > ScanPriority::Normal);
        assert!(ScanPriority::Normal > ScanPriority::Low);
    }
}
