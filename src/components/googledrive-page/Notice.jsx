import { Notice } from "@wordpress/components"

const NoticeAtTop = ({ notice, setNotice}) => {
    return (
        <Notice status={notice.type} isDismissible onRemove={() => setNotice({ message: '', type: '' })}>
            {notice.message}
        </Notice>
    )
}

export default NoticeAtTop