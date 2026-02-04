/* --- PIXEL PERFECTION - CORE ENGINE --- */

// Element Selection
const mainImage = document.getElementById('main-preview');

// Selectors updated to match the new Professional IDs in create.html
const brightnessSlider = document.getElementById('brightness');
const saturationSlider = document.getElementById('saturate');
const exposureSlider = document.getElementById('exposure'); 
const blurSlider = document.getElementById('blur'); 
const contrastSlider = document.getElementById('contrast');
const sharpSlider = document.getElementById('sharp');

// Store original filters for real-time adjustments
let filters = {
    brightness: 100,
    saturate: 100,
    exposure: 100,
    contrast: 100,
    sharp: 100,
    blur: 0
};

/* --- FILTER ENGINE --- */
function applyFilters() {
    if (!mainImage) return;
    
    /**
     * Applying Professional CSS filters.
     * Note: We use 'contrast' and 'brightness' twice in the logic to 
     * simulate high-end exposure layering.
     */
    mainImage.style.filter = `
        brightness(${filters.brightness}%)
        saturate(${filters.saturate}%)
        contrast(${filters.contrast}%)
        brightness(${filters.exposure}%)
        contrast(${filters.sharp}%)
        blur(${filters.blur}px)
    `;
}

/* --- EVENT LISTENERS FOR SLIDERS --- */
// Added listeners for the new 'Pixel Perfection' specific sliders
if(brightnessSlider) {
    brightnessSlider.addEventListener('input', (e) => {
        filters.brightness = e.target.value;
        applyFilters();
        updateVal('bright-badge', e.target.value);
    });
}

if(saturationSlider) {
    saturationSlider.addEventListener('input', (e) => {
        filters.saturate = e.target.value;
        applyFilters();
        updateVal('sat-badge', e.target.value);
    });
}

if(exposureSlider) {
    exposureSlider.addEventListener('input', (e) => {
        filters.exposure = e.target.value;
        applyFilters();
    });
}

if(blurSlider) {
    blurSlider.addEventListener('input', (e) => {
        // Subtle blur increments for professional results
        filters.blur = (e.target.value / 2); 
        applyFilters();
    });
}

if(contrastSlider) {
    contrastSlider.addEventListener('input', (e) => {
        filters.contrast = e.target.value;
        applyFilters();
    });
}

/* --- COMPARISON LOGIC --- */
// Allows the user to toggle between edited and original states
function showOriginal() {
    if (mainImage) {
        mainImage.style.transition = "0.3s cubic-bezier(0.4, 0, 0.2, 1)";
        mainImage.style.filter = 'none';
    }
}

function showEdited() {
    if (mainImage) {
        mainImage.style.transition = "0.3s cubic-bezier(0.4, 0, 0.2, 1)";
        applyFilters();
    }
}

/* --- ACCOUNT TAB FUNCTIONS --- */
// Controls the visibility of the side/account panel with smooth transitions
function openAccountTab() {
    const tab = document.getElementById('accountTab');
    if (tab) {
        tab.style.visibility = 'visible';
        tab.classList.add('active');
    }
}

function closeAccountTab() {
    const tab = document.getElementById('accountTab');
    if (tab) {
        tab.classList.remove('active');
        setTimeout(() => {
            tab.style.visibility = 'hidden';
        }, 600);
    }
}

/* --- UTILITY FUNCTIONS --- */
/**
 * Global update function for badge values next to sliders.
 * Updated to handle both percentages and degree symbols.
 */
function updateVal(id, val) {
    const badge = document.getElementById(id);
    if (badge) {
        const unit = id.includes('rot') ? "°" : "%";
        badge.innerText = val + unit;
    }
}