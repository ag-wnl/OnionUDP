use colored::*;

pub struct Logger;

/**
 * pretty print logs util
 */
impl Logger {
    pub fn info(message: &str) {
        println!("{} {}", "ℹ".blue(), message.white());
    }

    pub fn success(message: &str) {
        println!("{} {}", "✓".green(), message.green());
    }

    pub fn warning(message: &str) {
        println!("{} {}", "⚠".yellow(), message.yellow());
    }

    pub fn error(message: &str) {
        println!("{} {}", "✗".red(), message.red());
    }

    pub fn debug(message: &str) {
        println!("{} {}", "🔍".cyan(), message.cyan());
    }

    pub fn relay(message: &str) {
        println!("{} {}", "🔄".magenta(), message.magenta());
    }

    pub fn client(message: &str) {
        println!("{} {}", "👤".blue(), message.blue());
    }

    pub fn packet(message: &str) {
        println!("{} {}", "📦".green(), message.green());
    }

    pub fn circuit(message: &str) {
        println!("{} {}", "🔗".yellow(), message.yellow());
    }

    pub fn network(message: &str) {
        println!("{} {}", "🌐".cyan(), message.cyan());
    }
} 