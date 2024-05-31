document.addEventListener("DOMContentLoaded", () => {
    let btnInvio = document.getElementById("btnInvio")
    let input = document.getElementById("feedbackInput")
    let testo = document.getElementById("textSuccesso")
    let btnClose = document.getElementById("btnClose")

    btnInvio.addEventListener("click", () => {
        let url = "http://localhost:1337/api/feedbacks"
        testo.innerHTML = "";
        console.log(input.value)
        fetch(url, {
            method: "POST",
            body: JSON.stringify({
                data: {
                    Testo: `${input.value}`
                }
            }),
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }
        }).then(response => response.json()).then(json => {
            console.log(json)
            testo.innerHTML = "Feedback inviato correttamente! Grazie per la collaborazione"
        })
    })

    btnClose.addEventListener("click", () => {
        testo.innerHTML = ""
        input.value = ""
    })
})