var openedDropdown;

function hideCurrentDropdown() {
    if(openedDropdown) {
        openedDropdown.classList.remove('show');
        openedDropdown = undefined;
    }
}

window.addEventListener('click', e => {
    const { target } = e;

    if(target.getAttribute('data-toggle') !== 'dropdown') {
        hideCurrentDropdown();
        return;
    }

    const dropdown = target.parentNode.querySelector('.dropdown-menu');

    if(dropdown != openedDropdown) hideCurrentDropdown();
    dropdown.classList.toggle('show');
    if(dropdown.classList.contains('show')) openedDropdown = dropdown;
});