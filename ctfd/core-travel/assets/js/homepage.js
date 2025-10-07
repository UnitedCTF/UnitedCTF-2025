const CLOUD_COUNT = 16;

const clouds = document.querySelector('#cloud-container-inner');

for(let i = 0; i < CLOUD_COUNT; i++) {
    const windowWidth = window.innerWidth;

    const assetId = Math.floor(Math.random() * 4) + 1;
    const size = Math.random() * 10 + 10;
    const height = Math.random() * 10 - 5 + i * 10;
    const startX = Math.random() * windowWidth - 100;
    const speed = Math.random() * 40 + 10;

    const cloud = document.createElement('img');

    cloud.style['top'] = `${height}rem`;
    cloud.style['left'] = `${startX}px`;
    cloud.style['width'] = `${size}rem`;
    cloud.setAttribute('class', 'cloud');
    cloud.setAttribute('src', `/themes/core-travel/static/img/clouds/${assetId}.svg`);
    cloud.setAttribute('data-speed', speed);
    cloud.setAttribute('data-x', startX);

    clouds.appendChild(cloud);
}

var lastTime = Date.now();
function animate() {
    const windowWidth = window.innerWidth;

    const elapsedTime = (Date.now() - lastTime) / 1000;
    lastTime = Date.now();

    if(elapsedTime < .5) {
        for(let cloud of clouds.childNodes) {
            const realWidth = cloud.getBoundingClientRect().width;
            const speed = parseFloat(cloud.getAttribute('data-speed'));
            const currentX = parseFloat(cloud.getAttribute('data-x'));
            let newX = currentX + speed * elapsedTime;
            if(newX > windowWidth) newX = -realWidth;
            cloud.style['left'] = `${newX}px`;
            cloud.setAttribute('data-x', newX);
        }
    }

    requestAnimationFrame(animate);
}

if(!document.cookie.includes('lowdetail')) requestAnimationFrame(animate);