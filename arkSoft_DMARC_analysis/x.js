let commentList = [];
// replaceing the forEach with map to create a new array of objects
// comments.forEach((element) => commentList.push({
//     postId: element.postId,
//     id: element.id,
//     name: element.name,
//     email: element.email,
//     body: element.body
// }));
// or using map to create a new array of objects
// commentList = comments.map(element => ({
//     id: element.id,
//     name: element.name,
//     email: element.email,
//     body: element.body
// }))


async function fetchComments() {
    console.time('Async fetch time');
    const response = await fetch('https://jsonplaceholder.typicode.com/comments');

    if (response.status === 200) {
        const data = await response.json();
        renderComments(data);
    } else {
        console.error("Sunucu status kodu 200 değil:", response.status);
    }
    console.timeEnd('Async fetch time');
    console.log('Veri alındı:', response.status);
}


function syncFetchComments() {
   

    fetch('https://jsonplaceholder.typicode.com/comments')
        .then((response) => {
            if (response.status === 200) {
                return response.json();
            } else {
                throw new Error("Sunucu status kodu 200 değil: " + response.status);
            }
        })
        .then((data) => {
            renderComments(data);
        })
        .catch((error) => {
            console.error("Veri alınırken hata oluştu:", error);
        })
        
}

function renderComments(list) {

    list.forEach((element) => {
        console.log(`Post ID: ${element.postId} ID: ${element.id} Name: ${element.name} Email: ${element.email} Body: ${element.body}`);
    });
}

// console.log('Fetching comments async...');

// fetchComments();

// console.log('Fetching comments sync...');
console.time('Sync fetch time');
syncFetchComments();
console.timeEnd('Sync fetch time');