if(!doc[field] instanceof List){
        return false
}
switch (operator){
        case "==":
                return doc[field].size() == value_size
                break
        case ">=":
                return doc[field].size() >= value_size
                break
        case ">":
                return doc[field].size() > value_size
                break
        case "<=":
                return doc[field].size() <= value_size
                break
        case "<":
                return doc[field].size() < value_size
                break
        default:
                return false
                break
}
