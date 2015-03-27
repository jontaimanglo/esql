switch (operator){
        case "==":
                return doc[field].values.length == value_size
                break
        case ">=":
                return doc[field].values.length >= value_size
                break
        case ">":
                return doc[field].values.length > value_size
                break
        case "<=":
                return doc[field].values.length <= value_size
                break
        case "<":
                return doc[field].values.length < value_size
                break
        default:
                return false
                break
}
