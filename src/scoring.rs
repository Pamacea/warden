//! Security Scoring System
//!
//! Hardcore security grading system (A+ to F) based on OWASP, CWE, and security best practices.
//!
//! # Score Calculation
//!
//! - Maximum score: 100 points
//! - 10 categories, each with different weights
//! - Penalties for vulnerabilities
//! - Bonuses for best practices
//!
//! # Grades
//!
//! - **A+**: 95-100 (Excellent security)
//! - **A**: 90-94 (Very good security)
//! - **B**: 80-89 (Good security with issues)
//! - **C**: 70-79 (Fair security, needs improvement)
//! - **D**: 60-69 (Poor security, critical issues)
//! - **E**: 50-59 (Very poor security)
//! - **F**: 0-49 (Failing security)

pub mod categories;

use crate::scanners::{ScanReport, VulnSeverity, Target};
// Categories are used via explicit path, not wildcard import
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Security grade from A+ to F
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Grade {
    APlus,
    A,
    B,
    C,
    D,
    E,
    F,
}

impl Grade {
    /// Get grade from score
    pub fn from_score(score: f64) -> Self {
        if score >= 95.0 {
            Grade::APlus
        } else if score >= 90.0 {
            Grade::A
        } else if score >= 80.0 {
            Grade::B
        } else if score >= 70.0 {
            Grade::C
        } else if score >= 60.0 {
            Grade::D
        } else if score >= 50.0 {
            Grade::E
        } else {
            Grade::F
        }
    }

    /// Get display string for grade
    pub fn as_str(&self) -> &str {
        match self {
            Grade::APlus => "A+",
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::E => "E",
            Grade::F => "F",
        }
    }

    /// Get color for grade
    pub fn color(&self) -> colored::Color {
        match self {
            Grade::APlus | Grade::A => colored::Color::Green,
            Grade::B => colored::Color::Yellow,
            Grade::C => colored::Color::Yellow,
            Grade::D => colored::Color::Red,
            Grade::E => colored::Color::Red,
            Grade::F => colored::Color::Red,
        }
    }

    /// Get description for grade
    pub fn description(&self) -> &str {
        match self {
            Grade::APlus => "Excellent security posture",
            Grade::A => "Very good security posture",
            Grade::B => "Good security with minor issues",
            Grade::C => "Fair security, needs improvement",
            Grade::D => "Poor security, critical issues present",
            Grade::E => "Very poor security",
            Grade::F => "Failing security - immediate action required",
        }
    }
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Security finding with scoring impact
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Penalty {
    /// Category where penalty was applied
    pub category: String,
    /// Points deducted
    pub points: i32,
    /// Vulnerability title
    pub title: String,
    /// Vulnerability severity
    pub severity: VulnSeverity,
    /// CWE reference if available
    pub cwe: Option<String>,
}

/// Security bonus for best practices
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bonus {
    /// Category where bonus was applied
    pub category: String,
    /// Points awarded
    pub points: i32,
    /// Description of what earned the bonus
    pub description: String,
}

/// Security recommendation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority level
    pub priority: RecommendationPriority,
    /// Category
    pub category: String,
    /// Recommendation text
    pub text: String,
    /// Expected impact
    pub impact: i32,
}

/// Recommendation priority
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecommendationPriority::Critical => write!(f, "CRITICAL"),
            RecommendationPriority::High => write!(f, "HIGH"),
            RecommendationPriority::Medium => write!(f, "MEDIUM"),
            RecommendationPriority::Low => write!(f, "LOW"),
        }
    }
}

impl RecommendationPriority {
    fn color(&self) -> colored::Color {
        match self {
            RecommendationPriority::Critical => colored::Color::Red,
            RecommendationPriority::High => colored::Color::Red,
            RecommendationPriority::Medium => colored::Color::Yellow,
            RecommendationPriority::Low => colored::Color::Blue,
        }
    }
}

/// Category score
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryScore {
    /// Category name
    pub name: String,
    /// Score out of max_points
    pub score: i32,
    /// Maximum possible points
    pub max_points: i32,
    /// Penalties applied
    pub penalties: Vec<Penalty>,
    /// Bonuses applied
    pub bonuses: Vec<Bonus>,
}

impl CategoryScore {
    pub fn new(name: &'static str, max_points: i32) -> Self {
        Self {
            name: name.to_string(),
            score: max_points,
            max_points,
            penalties: Vec::new(),
            bonuses: Vec::new(),
        }
    }

    pub fn apply_penalty(&mut self, points: i32, title: String, severity: VulnSeverity, cwe: Option<String>) {
        self.score = (self.score - points).max(0);
        self.penalties.push(Penalty {
            category: self.name.clone(),
            points,
            title,
            severity,
            cwe,
        });
    }

    pub fn apply_bonus(&mut self, points: i32, description: String) {
        self.score = (self.score + points).min(self.max_points);
        self.bonuses.push(Bonus {
            category: self.name.clone(),
            points,
            description,
        });
    }

    pub fn percentage(&self) -> f64 {
        if self.max_points == 0 {
            0.0
        } else {
            (self.score as f64 / self.max_points as f64) * 100.0
        }
    }

    pub fn grade(&self) -> Grade {
        Grade::from_score(self.percentage())
    }
}

/// Complete security score
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityScore {
    /// Overall score (0-100)
    pub score: f64,
    /// Grade (A+ to F)
    pub grade: Grade,
    /// Target that was scored
    pub target: Target,
    /// Timestamp of scoring
    pub timestamp: String,
    /// Individual category scores
    pub categories: Vec<CategoryScore>,
    /// All penalties
    pub all_penalties: Vec<Penalty>,
    /// All bonuses
    pub all_bonuses: Vec<Bonus>,
    /// Recommendations
    pub recommendations: Vec<Recommendation>,
}

impl SecurityScore {
    /// Calculate security score from scan report
    pub fn calculate(report: &ScanReport) -> Self {
        let mut categories = Vec::new();

        // Calculate each category score
        let mut input_validation = categories::input_validation::calculate(report);
        let mut auth = categories::auth::calculate(report);
        let mut crypto = categories::crypto::calculate(report);
        let mut headers = categories::headers::calculate(report);
        let mut session = categories::session::calculate(report);
        let mut access_control = categories::access_control::calculate(report);
        let mut data_protection = categories::data_protection::calculate(report);
        let mut error_handling = categories::error_handling::calculate(report);
        let mut communications = categories::communications::calculate(report);
        let mut code_quality = categories::code_quality::calculate(report);

        // Collect all penalties and bonuses
        let mut all_penalties = Vec::new();
        let mut all_bonuses = Vec::new();

        for cat in [&mut input_validation, &mut auth, &mut crypto, &mut headers,
                     &mut session, &mut access_control, &mut data_protection, &mut error_handling,
                     &mut communications, &mut code_quality] {
            all_penalties.append(&mut cat.penalties.clone());
            all_bonuses.append(&mut cat.bonuses.clone());
        }

        categories.push(input_validation);
        categories.push(auth);
        categories.push(crypto);
        categories.push(headers);
        categories.push(session);
        categories.push(access_control);
        categories.push(data_protection);
        categories.push(error_handling);
        categories.push(communications);
        categories.push(code_quality);

        // Calculate total score (weighted sum / max points * 100)
        let total_score: i32 = categories.iter().map(|c| c.score).sum();
        let max_points: i32 = categories.iter().map(|c| c.max_points).sum();
        let score = if max_points > 0 {
            (total_score as f64 / max_points as f64) * 100.0
        } else {
            0.0
        };

        let grade = Grade::from_score(score);

        // Generate recommendations
        let recommendations = Self::generate_recommendations(&categories, &all_penalties);

        Self {
            score,
            grade,
            target: report.target.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            categories,
            all_penalties,
            all_bonuses,
            recommendations,
        }
    }

    /// Generate prioritized recommendations
    fn generate_recommendations(
        categories: &[CategoryScore],
        penalties: &[Penalty],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Critical recommendations from penalties
        for penalty in penalties {
            if penalty.severity == VulnSeverity::Critical {
                recommendations.push(Recommendation {
                    priority: RecommendationPriority::Critical,
                    category: penalty.category.clone(),
                    text: format!("Fix: {}", penalty.title),
                    impact: penalty.points,
                });
            }
        }

        // Category-specific recommendations
        for category in categories {
            if category.percentage() < 50.0 {
                recommendations.push(Recommendation {
                    priority: RecommendationPriority::High,
                    category: category.name.to_string(),
                    text: format!("Improve {} security posture (currently {:.0}%)",
                                  category.name, category.percentage()),
                    impact: category.max_points - category.score,
                });
            } else if category.percentage() < 80.0 {
                recommendations.push(Recommendation {
                    priority: RecommendationPriority::Medium,
                    category: category.name.to_string(),
                    text: format!("Address {} issues to reach best practices", category.name),
                    impact: category.max_points - category.score,
                });
            }
        }

        // Sort by priority and impact
        recommendations.sort_by(|a, b| {
            match (&a.priority, &b.priority) {
                (RecommendationPriority::Critical, RecommendationPriority::Critical) => b.impact.cmp(&a.impact),
                (RecommendationPriority::Critical, _) => std::cmp::Ordering::Less,
                (_, RecommendationPriority::Critical) => std::cmp::Ordering::Greater,
                (RecommendationPriority::High, RecommendationPriority::High) => b.impact.cmp(&a.impact),
                (RecommendationPriority::High, _) => std::cmp::Ordering::Less,
                (_, RecommendationPriority::High) => std::cmp::Ordering::Greater,
                _ => b.impact.cmp(&a.impact),
            }
        });

        // Limit to top 10 recommendations
        recommendations.truncate(10);
        recommendations
    }

    /// Render terminal output with ASCII art
    pub fn render_terminal(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "\n{}\n",
            "═".repeat(80).cyan()
        ));
        output.push_str(&format!(
            "{}  {}  {}\n",
            "║".cyan(),
            "SECURITY SCORE".bold().white(),
            "║".cyan()
        ));
        output.push_str(&format!(
            "{}\n",
            "═".repeat(80).cyan()
        ));

        // Score bar and grade
        output.push_str("\n");
        output.push_str(&format!(
            "  Overall Score: {}\n",
            format!("{:.1}/100", self.score).bold().white()
        ));

        // Grade display
        let grade_str = format!("  {}  ", self.grade.as_str());
        let grade_colored = match self.grade {
            Grade::APlus | Grade::A => grade_str.on_green().black().bold(),
            Grade::B | Grade::C => grade_str.on_yellow().black().bold(),
            Grade::D | Grade::E | Grade::F => grade_str.on_red().white().bold(),
        };
        output.push_str(&grade_colored);
        output.push_str(&format!("{}\n", self.grade.description()));

        // Progress bar
        output.push_str("\n  ");
        let bar_width = 50;
        let filled = ((self.score / 100.0) * bar_width as f64) as usize;
        let filled = filled.min(bar_width);

        let bar_color = if self.score >= 80.0 {
            colored::Color::Green
        } else if self.score >= 60.0 {
            colored::Color::Yellow
        } else {
            colored::Color::Red
        };

        for i in 0..bar_width {
            if i < filled {
                output.push_str(&"█".to_string().color(bar_color));
            } else {
                output.push_str(&"░".to_string().dimmed());
            }
        }
        output.push_str(&format!(" {:.0}%\n", self.score));

        // Category breakdown
        output.push_str(&format!(
            "\n{}\n",
            "─".repeat(80).dimmed()
        ));
        output.push_str(&format!(
            "{}\n",
            "Category Breakdown".bold().white()
        ));
        output.push_str(&format!(
            "{}\n",
            "─".repeat(80).dimmed()
        ));

        for category in &self.categories {
            output.push_str(&self.render_category_bar(category));
        }

        // Penalties
        if !self.all_penalties.is_empty() {
            output.push_str(&format!(
                "\n{}\n",
                "─".repeat(80).dimmed()
            ));
            output.push_str(&format!(
                "{}\n",
                "Penalties Applied".bold().red()
            ));
            output.push_str(&format!(
                "{}\n",
                "─".repeat(80).dimmed()
            ));

            for penalty in &self.all_penalties {
                let severity_colored = match penalty.severity {
                    VulnSeverity::Critical => "CRITICAL".red().bold(),
                    VulnSeverity::High => "HIGH".red().bold(),
                    VulnSeverity::Medium => "MEDIUM".yellow().bold(),
                    VulnSeverity::Low => "LOW".blue(),
                    VulnSeverity::Info => "INFO".white(),
                };

                output.push_str(&format!(
                    "  {} {} {} ({}) -{} pts\n",
                    "✗".red(),
                    severity_colored,
                    penalty.title,
                    penalty.category.dimmed(),
                    format!("{}", penalty.points).red().bold()
                ));

                if let Some(ref cwe) = penalty.cwe {
                    output.push_str(&format!(
                        "      {} {}\n",
                        "CWE:".dimmed(),
                        cwe.dimmed()
                    ));
                }
            }
        }

        // Bonuses
        if !self.all_bonuses.is_empty() {
            output.push_str(&format!(
                "\n{}\n",
                "─".repeat(80).dimmed()
            ));
            output.push_str(&format!(
                "{}\n",
                "Bonuses Awarded".bold().green()
            ));
            output.push_str(&format!(
                "{}\n",
                "─".repeat(80).dimmed()
            ));

            for bonus in &self.all_bonuses {
                output.push_str(&format!(
                    "  {} {} +{} pts - {}\n",
                    "✓".green(),
                    bonus.category.dimmed(),
                    format!("{}", bonus.points).green().bold(),
                    bonus.description
                ));
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            output.push_str(&format!(
                "\n{}\n",
                "─".repeat(80).dimmed()
            ));
            output.push_str(&format!(
                "{}\n",
                "Priority Recommendations".bold().yellow()
            ));
            output.push_str(&format!(
                "{}\n",
                "─".repeat(80).dimmed()
            ));

            for (i, rec) in self.recommendations.iter().enumerate() {
                let priority_colored = format!("{}", rec.priority)
                    .color(rec.priority.color())
                    .bold();

                output.push_str(&format!(
                    "  {} {} {} - {}\n",
                    format!("[{}]", i + 1).dimmed(),
                    priority_colored,
                    rec.category.dimmed(),
                    rec.text
                ));
                output.push_str(&format!(
                    "      {} Potential impact: +{} pts\n\n",
                    "→".dimmed(),
                    rec.impact
                ));
            }
        }

        // Footer
        output.push_str(&format!(
            "\n{}\n",
            "═".repeat(80).cyan()
        ));

        output
    }

    fn render_category_bar(&self, category: &CategoryScore) -> String {
        let mut output = String::new();

        let percentage = category.percentage();
        let grade = category.grade();

        // Category name and score
        output.push_str(&format!(
            "  {:.<20} ",
            category.name
        ));

        // Score display
        let score_str = format!("{}/{}", category.score, category.max_points);
        let score_colored = if percentage >= 80.0 {
            score_str.green()
        } else if percentage >= 60.0 {
            score_str.yellow()
        } else {
            score_str.red()
        };
        output.push_str(&format!("{:<8} ", score_colored));

        // Grade
        let grade_colored = format!("[{}]", grade.as_str())
            .color(grade.color())
            .bold();
        output.push_str(&format!("{:<4} ", grade_colored));

        // Progress bar
        let bar_width = 20;
        let filled = ((percentage / 100.0) * bar_width as f64) as usize;
        let filled = filled.min(bar_width);

        let bar_color = if percentage >= 80.0 {
            colored::Color::Green
        } else if percentage >= 60.0 {
            colored::Color::Yellow
        } else {
            colored::Color::Red
        };

        for i in 0..bar_width {
            if i < filled {
                output.push_str(&"█".to_string().color(bar_color));
            } else {
                output.push_str(&"░".to_string().dimmed());
            }
        }

        output.push_str(&format!(" {:.0}%\n", percentage));

        // Show penalty/bonus count
        let penalty_count = category.penalties.len();
        let bonus_count = category.bonuses.len();

        if penalty_count > 0 || bonus_count > 0 {
            output.push_str(&format!(
                "    {:<20} {} penalty(s), {} bonus(es)\n",
                "",
                format!("{}", penalty_count).red(),
                format!("{}", bonus_count).green()
            ));
        }

        output
    }

    /// Convert to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grade_from_score() {
        assert_eq!(Grade::from_score(100.0), Grade::APlus);
        assert_eq!(Grade::from_score(95.0), Grade::APlus);
        assert_eq!(Grade::from_score(90.0), Grade::A);
        assert_eq!(Grade::from_score(85.0), Grade::B);
        assert_eq!(Grade::from_score(75.0), Grade::C);
        assert_eq!(Grade::from_score(65.0), Grade::D);
        assert_eq!(Grade::from_score(55.0), Grade::E);
        assert_eq!(Grade::from_score(40.0), Grade::F);
        assert_eq!(Grade::from_score(0.0), Grade::F);
    }

    #[test]
    fn test_grade_display() {
        assert_eq!(Grade::APlus.as_str(), "A+");
        assert_eq!(Grade::A.as_str(), "A");
        assert_eq!(Grade::F.as_str(), "F");
    }

    #[test]
    fn test_category_score_new() {
        let cat = CategoryScore::new("Test", 10);
        assert_eq!(cat.name, "Test");
        assert_eq!(cat.score, 10);
        assert_eq!(cat.max_points, 10);
        assert_eq!(cat.percentage(), 100.0);
    }

    #[test]
    fn test_category_score_penalty() {
        let mut cat = CategoryScore::new("Test", 10);
        cat.apply_penalty(3, "Test penalty".to_string(), VulnSeverity::High, Some("CWE-123".to_string()));

        assert_eq!(cat.score, 7);
        assert_eq!(cat.penalties.len(), 1);
        assert_eq!(cat.penalties[0].points, 3);
        assert_eq!(cat.penalties[0].title, "Test penalty");
        assert_eq!(cat.percentage(), 70.0);
    }

    #[test]
    fn test_category_score_penalty_no_negative() {
        let mut cat = CategoryScore::new("Test", 10);
        cat.apply_penalty(15, "Huge penalty".to_string(), VulnSeverity::Critical, None);

        assert_eq!(cat.score, 0); // Should not go negative
    }

    #[test]
    fn test_category_score_bonus() {
        let mut cat = CategoryScore::new("Test", 10);
        cat.apply_bonus(2, "Good practice".to_string());

        assert_eq!(cat.score, 10); // Already at max
        assert_eq!(cat.bonuses.len(), 1);
    }

    #[test]
    fn test_category_score_bonus_after_penalty() {
        let mut cat = CategoryScore::new("Test", 10);
        cat.apply_penalty(3, "Penalty".to_string(), VulnSeverity::Medium, None);
        cat.apply_bonus(2, "Bonus".to_string());

        assert_eq!(cat.score, 9);
        assert_eq!(cat.percentage(), 90.0);
    }

    #[test]
    fn test_category_score_bonus_no_exceed_max() {
        let mut cat = CategoryScore::new("Test", 10);
        cat.apply_penalty(2, "Penalty".to_string(), VulnSeverity::Low, None);
        cat.apply_bonus(5, "Huge bonus".to_string());

        assert_eq!(cat.score, 10); // Should not exceed max
    }

    #[test]
    fn test_security_score_empty_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = SecurityScore::calculate(&report);

        // Empty report should have good score (no vulnerabilities found)
        assert!(score.score >= 90.0);
        assert!(matches!(score.grade, Grade::A | Grade::APlus));
    }
}
