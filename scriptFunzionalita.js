//SCRIPT 1A FUNZIONALITA'
document.addEventListener("DOMContentLoaded", function () {
    let select = document.getElementById("select1");
    let visualizza = document.getElementById("visualizza1");
    let modal_body = document.getElementById("modal-body1");
    let funzione1, funzione2;
    let url = "http://localhost:1337/api/cwe-weaknesses";
    fetch(url)
        .then(response => response.json())
        .then(funzione1 => {
            let datas = funzione1.data;
            let vulnerabilità;
            let Numero;
            let Testo;
            for (let data of funzione1.data) {
                Numero = data.attributes.Numero;
                Testo = data.attributes.Testo;
                vulnerabilità += `<option value="${Numero}">${Numero}-${Testo}</option>`;
            }
            select.innerHTML = vulnerabilità;

        });
    visualizza.addEventListener("click", () => {
        let urlPattern = `http://localhost:1337/api/patterns?fields[5]=Nome&filters[cwe_weaknesses][Numero][$eq]=${select.value}`;
        let patterns = "";
        fetch(urlPattern)
            .then(response => response.json())
            .then(funzione2 => {
                for (let data of funzione2.data) {
                    let Nome = data.attributes.Nome;
                    Nome = Nome.replace(/_/g, ' ');
                    patterns += `-${Nome}\n\n`;
                }
                modal_body.innerText = patterns;

            });

    });
});
//SCRIPT 2A FUNZIONALITA'
document.addEventListener("DOMContentLoaded", function () {
    let select = document.getElementById("select2");
    let visualizza = document.getElementById("visualizza2");
    let modal_body = document.getElementById("modal-body2");
    let funzione1, funzione2, selectElement;
    let url = "http://localhost:1337/api/patterns?fields[5]=Nome";
    fetch(url)
        .then(response => response.json())
        .then(funzione1 => {
            for (let data of funzione1.data) {
                let NomeValue = data.attributes.Nome;
                let NomeText = NomeValue.replace(/_/g, ' ');
                selectElement += `<option value="${NomeValue}">${NomeText}</option>`;
            }
            select.innerHTML = selectElement;

        });
    visualizza.addEventListener("click", () => {
        let urlPattern = `http://localhost:1337/api/esempis?fields[4]=Descrizione&fields[5]=Numero&filters[pattern][Nome][$eq]=${select.value}`;
        let patterns = "";
        fetch(urlPattern)
            .then(response => response.json())
            .then(funzione2 => {
                for (let data of funzione2.data) {
                    let Numero = data.attributes.Numero;
                    let Descrizione = data.attributes.Descrizione;
                    patterns += `-Esempio ${Numero}:\n${Descrizione}\n\n`;
                }
                if (patterns == "")
                    modal_body.innerText = "Nessun esempio associato";
                else
                    modal_body.innerText = patterns;

            });

    });
});
