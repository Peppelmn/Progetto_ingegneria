
document.addEventListener("DOMContentLoaded", () => {
    let url = "http://localhost:1337/api/newses?sort[1]=createdAt:desc"

    fetch(url).then(response => response.json()).then(json => {
        let body = document.getElementById("news-body")
        let testo = "";
        for (let datas of json.data) {
            let dataN = datas.attributes.createdAt
            let arrayTempo = dataN.split("T")
            dataN = arrayTempo[0]
            let oraN = arrayTempo[1].split(".")[0]
            testo += `<div class="card">
                <div class="card-header">${dataN} ${oraN}</div>
                <div class="card-body">
                    <div class="card-text">
                        ${datas.attributes.Testo}
                    </div>
                </div>
            </div><br>`;
        }
        body.innerHTML = testo;
    })
})
