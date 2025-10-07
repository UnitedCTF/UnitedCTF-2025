const checkForm = document.getElementById('check-form');

checkForm.onsubmit = async e => {
    e.preventDefault();

    const data = new FormData(checkForm);
    const json = {};
    data.forEach((value, key) => json[key] = value);

    const resp = await fetch('/api/check', {
        method: 'POST',
        body: JSON.stringify(json),
        headers: {
            'Content-Type': 'application/json'
        }
    });

    if(resp.status == 401) {
        alert("La clé de chambre que vous avez fourni est invalide ou n'est pas associée à la chambre en question.");
        return;
    }

    const { breached } = await resp.json();
    if(breached) {
        alert("Nous avons le regret de vous informer que vous avez été affecté par la brèche.");
    } else {
        alert("Bonne nouvelle! Vous n'avez pas été affecté par la brèche.");
    }
};