/**
 * Common JavaScript functions for the Furniture Order Management System
 */

// Auto-close flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    // Auto close alerts
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Highlight active menu item
    const currentPath = window.location.pathname;
    const currentSearch = window.location.search;
    const navLinks = document.querySelectorAll('.navbar .nav-link');
    
    navLinks.forEach(function(link) {
        const linkPath = link.getAttribute('href');
        
        if (linkPath === currentPath || 
            linkPath === currentPath + currentSearch || 
            (currentPath.includes('/edit/') && linkPath === '/')) {
            link.classList.add('active');
            link.setAttribute('aria-current', 'page');
        }
    });
});

// Format phone numbers as user types (XXX-XXXX-XXXX)
function formatPhoneNumber(input) {
    const value = input.value.replace(/\D/g, '');
    let formattedValue = '';
    
    if (value.length > 0) {
        formattedValue = value.substring(0, 3);
        
        if (value.length > 3) {
            formattedValue += '-' + value.substring(3, 7);
        }
        
        if (value.length > 7) {
            formattedValue += '-' + value.substring(7, 11);
        }
    }
    
    input.value = formattedValue;
}

// Phone input event handler (attach to phone inputs)
const phoneInputs = document.querySelectorAll('input[name="phone"]');
phoneInputs.forEach(function(input) {
    input.addEventListener('input', function() {
        formatPhoneNumber(this);
    });
}); 