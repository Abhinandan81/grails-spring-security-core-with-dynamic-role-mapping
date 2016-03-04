package com.auth

class RequestMap {
    String url
    static belongsTo    = [Role]
    static hasMany      = [roles : Role]

    static constraints = {
    }
}
