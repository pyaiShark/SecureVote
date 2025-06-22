document.addEventListener('DOMContentLoaded', function() {
    // Password strength indicator
    const passwordInputs = document.querySelectorAll('input[name="new_password"]');
    
    passwordInputs.forEach(input => {
        input.addEventListener('input', function() {
            const password = this.value;
            const strengthMeter = this.parentElement.nextElementSibling.querySelector('.password-strength-meter');
            
            if (!strengthMeter) return;
            
            // Reset strength meter
            strengthMeter.style.width = '0%';
            strengthMeter.style.backgroundColor = '#e9ecef';
            
            if (password.length === 0) return;
            
            // Calculate strength
            let strength = 0;
            if (password.length >= 8) strength += 25;
            if (/[A-Z]/.test(password)) strength += 25;
            if (/[0-9]/.test(password)) strength += 25;
            if (/[^A-Za-z0-9]/.test(password)) strength += 25;
            
            // Update meter
            strengthMeter.style.width = strength + '%';
            
            // Set color based on strength
            if (strength < 50) {
                strengthMeter.style.backgroundColor = '#dc3545'; // Red
            } else if (strength < 75) {
                strengthMeter.style.backgroundColor = '#ffc107'; // Yellow
            } else {
                strengthMeter.style.backgroundColor = '#28a745'; // Green
            }
        });
    });
});