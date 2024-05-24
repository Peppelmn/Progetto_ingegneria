
class GestioineFunzionalità {
    constructor() { }

    getPrivacyPatternFromWeakness() {
        let select = document.getElementById("select1");
        let visualizza = document.getElementById("visualizza1");
        let modal_body = document.getElementById("modal-body1");
        let url = "http://localhost:1337/api/cwe-weaknesses?fields[0]=Testo&fields[4]=Numero&sort[0]=Testo:asc";
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
            let urlPattern = `http://localhost:1337/api/patterns?fields[5]=Nome&filters[cwe_weaknesses][Numero][$eq]=${select.value}&sort[5]=Nome:asc`;
            let patterns = "";
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    for (let data of funzione2.data) {
                        let Nome = data.attributes.Nome;
                        Nome = Nome.replace(/_/g, ' ');
                        patterns += `-${Nome}\n\n`;
                    }
                    modal_body = patterns

                });

        });
    }

    getExampleFromPattern() {
        let select = document.getElementById("select2");
        let visualizza = document.getElementById("visualizza2");
        let modal_body = document.getElementById("modal-body2");
        let selectElement;
        let url = "http://localhost:1337/api/patterns?fields[5]=Nome&sort[5]=Nome:asc";
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
            let text = "";
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    for (let data of funzione2.data) {
                        let Numero = data.attributes.Numero;
                        let Descrizione = data.attributes.Descrizione;
                        text += `<b>-Esempio ${Numero}:</b><br>${Descrizione}<br><br>`;
                    }
                    if (text == "")
                        modal_body.innerHTML = "Nessun esempio associato";
                    else
                        modal_body.innerHTML = text;

                });

        });
    }

    getPatternFromGDPR() {
        let select = document.getElementById("select3");
        let visualizza = document.getElementById("visualizza3");
        let modal_body = document.getElementById("modal-body3");
        let selectElement;
        let url = "http://localhost:1337/api/gdpr-articles?fields[0]=Numero&fields[1]=Nome&sort[1]=Nome";
        fetch(url)
            .then(response => response.json())
            .then(funzione1 => {
                for (let data of funzione1.data) {
                    let Nome = data.attributes.Nome;
                    let Numero = data.attributes.Numero;
                    selectElement += `<option value="${Numero}">Articolo ${Numero}: ${Nome}</option>`;
                }
                select.innerHTML = selectElement;

            });
        visualizza.addEventListener("click", () => {
            let urlPattern = `http://localhost:1337/api/patterns?fields[5]=Nome&filters[gdpr_articles][Numero][$eq]=${select.value}&sort[5]=Nome:asc`;
            let text = "";
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    console.log(funzione2);
                    for (let data of funzione2.data) {
                        let Nome = data.attributes.Nome;
                        Nome = Nome.replace(/_/g, ' ');
                        text += `-${Nome}<br><br>`;
                    }
                    modal_body.innerHTML = text;
                });
        });
    }

    getElementsFromPattern() {
        let select = document.getElementById("select4");
        let visualizza = document.getElementById("visualizza4");
        let modal_body = document.getElementById("modal-body4");
        let selectElement;
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
            let urlPattern = `http://localhost:1337/api/patterns?fields[5]=Nome&filters[Nome][$eq]=${select.value}&populate[strategies][fields][0]=Nome&populate[cwe_weaknesses][fields][4]=Numero&populate[cwe_weaknesses][fields][5]=Testo&populate[mvcs][fields][0]=Nome&populate[iso_phases][fields][0]=Numero&populate[iso_phases][fields][1]=Titolo&populate[gdpr_articles][fields][0]=Numero&populate[gdpr_articles][fields][1]=Nome&populate[owasp_categories][fields][1]=Codice&populate[owasp_categories][fields][0]=Testo&populate[pb_d_principles][fields][0]=Testo&fields[1]=Descrizione&fields[0]=Contesto`;
            let text = "", textTemp = "";
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    for (let data of funzione2.data) {

                        text += `<b>Descrizione:</b><br>`;
                        let des = data.attributes.Descrizione;
                        text += `${des}<br><br>`

                        text += `<b>Contesto:</b><br>`;
                        let cont = data.attributes.Contesto;
                        text += `${cont}<br><br>`

                        text += `<b>Strategie:</b><br>`;
                        let str = data.attributes.strategies.data;
                        for (let strs of str) {
                            text += `-${strs.attributes.Nome}<br>`;
                        }
                        text += "<br>";

                        text += `<b>Vulnerabilità CWE:</b><br>`;
                        let cwe = data.attributes.cwe_weaknesses.data;
                        for (let cwes of cwe) {
                            text += `-${cwes.attributes.Numero}: ${cwes.attributes.Testo}<br>`;
                        }
                        text += "<br>";

                        text += `<b>Articoli GDPR:</b><br>`;
                        let gdpr = data.attributes.gdpr_articles.data;
                        for (let gdprs of gdpr) {
                            textTemp = `-${gdprs.attributes.Numero}: ${gdprs.attributes.Nome}<br>`;
                        }
                        if (textTemp == "")
                            text += "Non ci sono articoli GDPR associati a questo pattern<br>";
                        else text += textTemp;
                        text += "<br>";

                        text += `<b>Fasi ISO:</b><br>`;
                        let iso = data.attributes.iso_phases.data;
                        for (let isos of iso) {
                            text += `-${isos.attributes.Numero}: ${isos.attributes.Titolo}<br>`;
                        }
                        text += "<br>";

                        text += `<b>Componenti MVC:</b><br>`;
                        let mvc = data.attributes.mvcs.data;
                        for (let mvcs of mvc) {
                            text += `-${mvcs.attributes.Nome}<br>`;
                        }
                        text += "<br>";

                        text += `<b>Categorie OWASP:</b><br>`;
                        let owasp = data.attributes.owasp_categories.data;
                        for (let owasps of owasp) {
                            text += `-${owasps.attributes.Codice}: ${owasps.attributes.Testo}<br>`;
                        }
                        text += "<br>";

                        text += `<b>Principi Privacy By Design:</b><br>`;
                        let pbd = data.attributes.pb_d_principles.data;
                        for (let pbds of pbd) {
                            text += `-${pbds.attributes.Testo}<br>`;
                        }
                        text += "<br>";

                    }
                    modal_body.innerHTML = text;
                });

        });
    }

    getPBDFromISO() {
        let select = document.getElementById("select5");
        let visualizza = document.getElementById("visualizza5");
        let modal_body = document.getElementById("modal-body5");
        let selectElement;
        let url = "http://localhost:1337/api/iso-phases?fields[0]=Numero&fields[1]=Titolo&sort[0]=Numero:asc";
        fetch(url)
            .then(response => response.json())
            .then(funzione1 => {
                for (let data of funzione1.data) {
                    let Titolo = data.attributes.Titolo;
                    let Numero = data.attributes.Numero;
                    selectElement += `<option value="${Numero}">Fase ${Numero}: ${Titolo}</option>`;
                }
                select.innerHTML = selectElement;

            });
        visualizza.addEventListener("click", () => {
            let urlPattern = `http://localhost:1337/api/iso-phases?fields[0]=Numero&populate[patterns][fields][5]=Nome&populate[patterns][populate][0]=pb_d_principles&filters[Numero][$eq]=${select.value}`;
            let text = "";
            let vettore = [];
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    for (let data of funzione2.data) {
                        let arrayPatterns = data.attributes.patterns.data;
                        for (let pattern of arrayPatterns) {
                            let arrayPBD = pattern.attributes.pb_d_principles.data;
                            for (let pbd of arrayPBD) {
                                let Testo = pbd.attributes.Testo;
                                vettore.push(Testo);
                            }
                        }
                    }
                    let vettoreSenzaDuplicati = new Set(vettore);
                    vettore = [...vettoreSenzaDuplicati];
                    for (let v of vettore) {
                        text += `${v}<br>`;
                    }
                    modal_body.innerHTML = text;
                });

        });
    }

    getISOFromMVC() {
        let select = document.getElementById("select6");
        let visualizza = document.getElementById("visualizza6");
        let modal_body = document.getElementById("modal-body6");
        let selectElement;
        let url = "http://localhost:1337/api/mvcs";
        fetch(url)
            .then(response => response.json())
            .then(funzione1 => {
                for (let data of funzione1.data) {
                    selectElement += `<option value="${data.attributes.Nome}">${data.attributes.Nome}</option>`;
                }
                select.innerHTML = selectElement;

            });
        visualizza.addEventListener("click", () => {
            let urlPattern = `http://localhost:1337/api/mvcs?fields[0]=Nome&populate[patterns][fields][5]=Nome&populate[patterns][populate][0]=iso_phases&filters[Nome][$eq]=${select.value}`;
            let text = "";
            let vettore = [];
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    for (let data of funzione2.data) {
                        let arrayPatterns = data.attributes.patterns.data;
                        for (let pattern of arrayPatterns) {
                            let arrayISO = pattern.attributes.iso_phases.data;
                            for (let iso of arrayISO) {
                                let Testo = `${iso.attributes.Numero} - ${iso.attributes.Titolo}`;
                                vettore.push(Testo);
                            }
                        }
                    }
                    let vettoreSenzaDuplicati = new Set(vettore);
                    vettore = [...vettoreSenzaDuplicati];
                    for (let v of vettore) {
                        text += `${v}<br>`;
                    }
                    modal_body.innerHTML = text;
                });

        });
    }

    getCWEFromGDPR() {
        let select = document.getElementById("select7");
        let visualizza = document.getElementById("visualizza7");
        let modal_body = document.getElementById("modal-body7");
        let selectElement;
        let url = "http://localhost:1337/api/gdpr-articles?fields[0]=Numero&fields[1]=Nome&sort[1]=Nome";
        fetch(url)
            .then(response => response.json())
            .then(funzione1 => {
                for (let data of funzione1.data) {
                    selectElement += `<option value="${data.attributes.Numero}">Articolo ${data.attributes.Numero}: ${data.attributes.Nome}</option>`;
                }
                select.innerHTML = selectElement;

            });
        visualizza.addEventListener("click", () => {
            let urlPattern = `http://localhost:1337/api/gdpr-articles?fields[0]=Numero&fields[1]=Nome&populate[patterns][fields][5]=Nome&populate[patterns][populate][0]=cwe_weaknesses&filters[Numero][$eq]=${select.value}`;
            let text = "";
            let vettore = [];
            fetch(urlPattern)
                .then(response => response.json())
                .then(funzione2 => {
                    console.log(funzione2);
                    for (let data of funzione2.data) {
                        let arrayPatterns = data.attributes.patterns.data;
                        for (let pattern of arrayPatterns) {
                            let arrayCWE = pattern.attributes.cwe_weaknesses.data;
                            for (let cwe of arrayCWE) {
                                let Testo = `${cwe.attributes.Numero} - ${cwe.attributes.Testo}`;
                                vettore.push(Testo);
                            }
                        }
                    }
                    let vettoreSenzaDuplicati = new Set(vettore);
                    vettore = [...vettoreSenzaDuplicati];
                    for (let v of vettore) {
                        text += `${v}<br>`;
                    }
                    modal_body.innerHTML = text;
                });

        });
    }
}

let funzionalità = new GestioineFunzionalità();

funzionalità.getPrivacyPatternFromWeakness();
funzionalità.getExampleFromPattern();
funzionalità.getPatternFromGDPR();
funzionalità.getElementsFromPattern();
funzionalità.getPBDFromISO();
funzionalità.getISOFromMVC();
funzionalità.getCWEFromGDPR();