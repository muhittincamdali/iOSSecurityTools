import Foundation
import iOSSecurityTools

/// Basic example demonstrating the core functionality of iOSSecurityTools
@main
struct BasicExample {
    static func main() {
        print("🚀 iOSSecurityTools Basic Example")
        
        // Initialize the framework
        let framework = iOSSecurityTools()
        
        // Configure with default settings
        framework.configure()
        
        print("✅ Framework configured successfully")
        
        // Demonstrate basic functionality
        demonstrateBasicFeatures(framework)
    }
    
    static func demonstrateBasicFeatures(_ framework: iOSSecurityTools) {
        print("\n📱 Demonstrating basic features...")
        
        // Add your example code here
        print("🎯 Feature 1: Core functionality")
        print("🎯 Feature 2: Configuration")
        print("🎯 Feature 3: Error handling")
        
        print("\n✨ Basic example completed successfully!")
    }
}
