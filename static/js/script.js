/**
 * Common JavaScript functions for the Furniture Order Management System
 */

// Auto-close flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    // Auto close alerts
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            if (alert && typeof bootstrap !== 'undefined') {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
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

    // 전화번호 입력 필드 초기화 및 이벤트 바인딩
    initializePhoneInputs();
});

// 전화번호 입력 필드 초기화 및 이벤트 바인딩
function initializePhoneInputs() {
    const phoneInputs = document.querySelectorAll('input[name="phone"]');
    const manualPhoneCheckbox = document.getElementById('manual_phone_input');

    phoneInputs.forEach(function(phoneInput) {
        // 페이지 로드 시 초기 포맷팅 적용
        applyConditionalPhoneFormatting(phoneInput);

        // 입력 중 포맷팅 적용
        phoneInput.addEventListener('input', function() {
            applyConditionalPhoneFormatting(this);
        });
    });

    if (manualPhoneCheckbox) {
        // 체크박스 변경 시 포맷팅 재적용
        manualPhoneCheckbox.addEventListener('change', function() {
            phoneInputs.forEach(function(phoneInput) {
                applyConditionalPhoneFormatting(phoneInput);
            });
        });
    }

    // 테이블 내 전화번호 셀에 포맷팅 적용
    formatTablePhoneNumbers();
}

// 테이블의 전화번호 셀 포맷팅 적용
function formatTablePhoneNumbers() {
    document.querySelectorAll('td.th-phone').forEach(cell => {
        const phoneNumber = cell.textContent.trim();
        if (phoneNumber) {
            cell.textContent = formatKoreanPhoneNumber(phoneNumber);
        }
    });
}

// 전화번호 포맷팅 함수
function formatKoreanPhoneNumber(phoneNumber) {
    if (!phoneNumber) return '';
    
    // 숫자만 추출
    const cleanedNumber = phoneNumber.replace(/[^0-9]/g, '');
    const length = cleanedNumber.length;

    if (length < 8) {
        return phoneNumber; // 너무 짧으면 원래 값 반환
    } else if (length === 8) {
        return cleanedNumber.slice(0, 4) + '-' + cleanedNumber.slice(4); // 0xxx-xxxx (일부 지역번호 없는 경우 또는 15xx, 16xx 등)
    } else if (length === 9) {
        return cleanedNumber.slice(0, 2) + '-' + cleanedNumber.slice(2, 5) + '-' + cleanedNumber.slice(5); // 02-xxx-xxxx
    } else if (length === 10) {
        if (cleanedNumber.startsWith('02')) {
            return cleanedNumber.slice(0, 2) + '-' + cleanedNumber.slice(2, 6) + '-' + cleanedNumber.slice(6); // 02-xxxx-xxxx
        } else if (cleanedNumber.startsWith('0504')) {
            return cleanedNumber.slice(0, 4) + '-' + cleanedNumber.slice(4, 7) + '-' + cleanedNumber.slice(7); // 0504-xxx-xxxx (가상 번호)
        } else {
            return cleanedNumber.slice(0, 3) + '-' + cleanedNumber.slice(3, 6) + '-' + cleanedNumber.slice(6); // 0xx-xxx-xxxx (010, 031 등)
        }
    } else if (length === 11) {
        return cleanedNumber.slice(0, 3) + '-' + cleanedNumber.slice(3, 7) + '-' + cleanedNumber.slice(7); // 0xx-xxxx-xxxx (대부분의 휴대폰 번호)
    } else if (length === 12) {
        return cleanedNumber.slice(0, 4) + '-' + cleanedNumber.slice(4, 8) + '-' + cleanedNumber.slice(8); // 050x-xxxx-xxxx (가상 번호)
    } else {
        return phoneNumber; // 너무 길면 원래 값 반환
    }
}

// 조건부 전화번호 포맷팅 적용
function applyConditionalPhoneFormatting(phoneInputElement) {
    const manualCheckbox = document.getElementById('manual_phone_input');

    if (manualCheckbox && manualCheckbox.checked) {
        // 수동 입력 모드: 사용자가 입력한 내용 그대로 둠
        return;
    }

    // 자동 하이픈 추가 모드
    let currentValue = phoneInputElement.value;
    phoneInputElement.value = formatKoreanPhoneNumber(currentValue);
}

// Format phone numbers as user types (XXX-XXXX-XXXX)
function formatPhoneNumber(input) {
    // 숫자 이외의 문자 모두 제거
    input.value = input.value.replace(/\D/g, '');
}

// Phone input event handler (attach to phone inputs)
/*
const phoneInputs = document.querySelectorAll('input[name="phone"]');
phoneInputs.forEach(function(input) {
    input.addEventListener('input', function() {
        formatPhoneNumber(this);
    });
}); 
*/ 