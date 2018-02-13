from electrum.i18n import _

fullname = 'Timestamp'
description = '%s\n%s' % (_("Plugin to include the timestamps of some data inside your transaction."),
                          _("The final timestamp will include the timestamps of your data and the timestamps " +
                            "collected by some aggregators (calendar services). \nTo perform this operations it is " +
                            "used the OpenTimestamps standard."))

available_for = ['qt']
