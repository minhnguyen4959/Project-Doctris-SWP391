function SwalDelete(url, data, redirectUrl) {
    swal({
        title: 'Are you sure?',
        text: 'It will be deleted permanently',
        icon: 'warning',
        buttons: ["Cancel", "Delete"],
        dangerMode: true,
        closeModal: true,
        allowOutsideClick: false,
    }).then(result => {
        console.log(result)
        if (result === true) {
            return new Promise(function (resolve) {
                $.ajax({
                    url,
                    type: 'POST',
                    data,
                })
                    .done(function (response) {
                        console.log(response)
                        setTimeout(() => {
                            window.location.href = redirectUrl;
                        }, 1000)
                        swal('Deleted!', "Successfully deleted!", "success");
                    })
                    .fail(function (error) {
                        console.log(error);
                        swal(
                            'Oops...',
                            'Something went wrong!',
                            'error'
                        );
                    });
            });
        }
    });
}

function SwalStatus(url, data, redirectUrl, message) {
    swal({
        title: 'Are you sure?',
        text: 'Appointment will be cancel',
        icon: 'warning',
        buttons: ["Cancel", "Accepted"],
        dangerMode: true,
        closeModal: true,
        allowOutsideClick: false,
    }).then(result => {
        console.log(result)
        if (result === true) {
            return new Promise(function (resolve) {
                $.ajax({
                    url,
                    type: 'POST',
                    data,
                })
                    .done(function (response) {
                        console.log(response)
                        setTimeout(() => {
                            window.location.href = redirectUrl;
                        }, 1000)
                        swal('Update!', message, "success");
                    })
                    .fail(function (error) {
                        console.log(error);
                        swal(
                            'Oops...',
                            'Something went wrong!',
                            'error'
                        );
                    });
            });
        }
    });
}

function SwalComplete(url, data, redirectUrl, message) {
    swal({
        title: 'Did you have to complete appointment?',
        text: 'Appointment will be change to completed',
        icon: 'warning',
        buttons: ["Cancel", "Accepted"],
        dangerMode: true,
        closeModal: true,
        allowOutsideClick: false,
    }).then(result => {
        console.log(result)
        if (result === true) {
            return new Promise(function (resolve) {
                $.ajax({
                    url,
                    type: 'POST',
                    data,
                })
                    .done(function (response) {
                        console.log(response)
                        setTimeout(() => {
                            window.location.href = redirectUrl;
                        }, 1000)
                        swal('Update!', message, "success");
                    })
                    .fail(function (error) {
                        console.log(error);
                        swal(
                            'Oops...',
                            'Something went wrong!',
                            'error'
                        );
                    });
            });
        }
    });
}

function SwalDelete2(url, element, data) {
    swal({
        title: 'Are you sure?',
        text: 'It will be deleted permanently',
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, delete it!',
        showLoaderOnConfirm: true,

        preConfirm: function () {
            return new Promise(function (resolve) {
                $.ajax({
                    url,
                    type: 'POST',
                    data,
                })
                    .done(function (response) {
                        console.log(response)
                        swal('Deleted!', "Successfully deleted!", "success");
                        element.remove();
                    })
                    .fail(function (error) {
                        console.log(error);
                        swal(
                            'Oops...',
                            'Something went wrong!',
                            'error'
                        );
                    });
            });
        },
        allowOutsideClick: false,
    });
}

function toastSuccessful(mes) {
    toastr.options.positionClass = 'toast-top-right';
    toastr.options.timeOut = 4000;
    toastr.success(mes);
}

function toastFail(mes) {
    toastr.options.positionClass = 'toast-top-right';
    toastr.options.timeOut = 4000;
    toastr.error(mes);
}

function changeStatus(url) {
    $('#myTable').on('click', '.changeStatus', function (e) {
        var id = $(this).attr('data-id');
        console.log(id)
        $.ajax({
            type: 'POST',
            url,
            data: {
                id,
                action: "updateStatus"
            },
            success: function (data) {
                console.log(data);
                toastr.options.positionClass = 'toast-top-right';
                toastr.options.timeOut = 4000;
                toastr.success("Status succesfully changed");
            },
            error: function (error) {
                console.log(error);
                toastr.options.positionClass = 'toast-top-right';
                toastr.options.timeOut = 4000;
                toastr.error("Change status failed");
            }
        });
    });
}
