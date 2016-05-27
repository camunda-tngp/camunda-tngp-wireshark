$4=="request" {
    request[$2] = $3
}

$4=="response" {
    response[$2] = $3
}

END {
    for (r in request) {
        print r, response[r] - request[r]
    }
}
