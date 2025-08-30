package com.kerb4j.integration;

import com.kerb4j.integration.api.KerberosClientFactory;
import com.kerb4j.integration.api.KerberosClientProvider;

/**
 * Simple demonstration of the new integration layer
 */
public class IntegrationDemo {
    public static void main(String[] args) {
        System.out.println("=== Kerb4J Integration Layer Demo ===\n");
        
        // Discover available implementations
        System.out.println("1. Available Kerberos implementations:");
        try {
            KerberosClientFactory jdkFactory = KerberosClientProvider.getFactory("JDK");
            System.out.println("   ✓ " + jdkFactory.getImplementationName() + " implementation available");
        } catch (Exception e) {
            System.out.println("   ✗ JDK implementation not available: " + e.getMessage());
        }
        
        try {
            KerberosClientFactory kerbyFactory = KerberosClientProvider.getFactory("Apache Kerby");
            System.out.println("   ✓ " + kerbyFactory.getImplementationName() + " implementation available");
        } catch (Exception e) {
            System.out.println("   ✗ Apache Kerby implementation not available: " + e.getMessage());
        }
        
        // Show default implementation
        System.out.println("\n2. Default implementation:");
        KerberosClientFactory defaultFactory = KerberosClientProvider.getDefaultFactory();
        System.out.println("   Default: " + defaultFactory.getImplementationName());
        
        // Demonstrate factory switching
        System.out.println("\n3. Implementation switching:");
        try {
            KerberosClientFactory originalDefault = KerberosClientProvider.getDefaultFactory();
            System.out.println("   Original default: " + originalDefault.getImplementationName());
            
            // Try to switch to different implementation
            String[] implementations = {"JDK", "Apache Kerby"};
            for (String impl : implementations) {
                try {
                    KerberosClientFactory factory = KerberosClientProvider.getFactory(impl);
                    KerberosClientProvider.setDefaultFactory(factory);
                    System.out.println("   Switched to: " + KerberosClientProvider.getDefaultFactory().getImplementationName());
                } catch (Exception e) {
                    System.out.println("   Failed to switch to " + impl + ": " + e.getMessage());
                }
            }
            
            // Restore original
            KerberosClientProvider.setDefaultFactory(originalDefault);
            System.out.println("   Restored to: " + KerberosClientProvider.getDefaultFactory().getImplementationName());
            
        } catch (Exception e) {
            System.out.println("   Error during switching demo: " + e.getMessage());
        }
        
        System.out.println("\n=== Demo Complete ===");
        System.out.println("\nThe integration layer provides:");
        System.out.println("• Pluggable Kerberos implementations");
        System.out.println("• Service discovery via SPI");
        System.out.println("• Runtime implementation switching");
        System.out.println("• Full backward compatibility");
        System.out.println("• Consistent API across implementations");
    }
}