const resetForm = document.getElementById('reset-form');

resetForm.onsubmit = async e => {
    e.preventDefault();

    const data = new FormData(resetForm);
    const json = {};
    data.forEach((value, key) => json[key] = value);

    const resp = await fetch('/api/reset', {
        method: 'POST',
        body: JSON.stringify(json),
        headers: {
            'Content-Type': 'application/json'
        }
    });

    alert("Une nouvelle clé de chambre a été émise et a été glissée sous votre porte de chambre.");
};