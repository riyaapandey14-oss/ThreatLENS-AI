// ThreatLens AI - Frontend JavaScript

function toggleMenu() {
    const menu = document.getElementById('mobileMenu');
    menu.classList.toggle('active');
}

function showLoading() {
    const btns = document.querySelectorAll('.btn');
    btns.forEach(btn => {
        const text = btn.querySelector('.btn-text');
        const loader = btn.querySelector('.btn-loader');
        if (text && loader) {
            text.classList.add('hidden');
            loader.classList.remove('hidden');
        }
        btn.disabled = true;
    });
}

function prefillQuestion(text) {
    const input = document.querySelector('.chat-input');
    if (input) {
        input.value = text;
        input.focus();
    }
}

// Update quiz progress bar and highlight selected options
document.addEventListener('DOMContentLoaded', function() {
    const questions = document.querySelectorAll('.quiz-question');
    const progressBar = document.getElementById('progressBar');
    const total = questions.length;

    function updateProgress() {
        let answered = 0;
        questions.forEach(q => {
            const checked = q.querySelector('input[type="radio"]:checked');
            if (checked) answered++;
        });
        if (progressBar) {
            progressBar.style.width = (answered / total * 100) + '%';
        }
    }

    questions.forEach(q => {
        const radios = q.querySelectorAll('input[type="radio"]');
        radios.forEach(r => {
            r.addEventListener('change', function() {
                // Remove selected class from all labels in this question
                const allLabels = q.querySelectorAll('.option-label');
                allLabels.forEach(l => l.classList.remove('selected'));
                // Add selected class to the parent label of the checked radio
                if (this.checked) {
                    this.closest('.option-label').classList.add('selected');
                }
                updateProgress();
            });
        });
    });

    // Initial progress
    updateProgress();
});
