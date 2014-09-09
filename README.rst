======================
reverse-users-formula
======================

Formula to configure user via pillar in a user/hosts rather than host/users manner.


.. note::

    See the full `Salt Formulas installation and usage instructions
    <http://docs.saltstack.com/topics/development/conventions/formulas.html>`_.

Available states
================

.. contents::
    :local:

``users``
---------

Configure a users via pillar. Anything availble in http://docs.saltstack.com/en/latest/ref/states/all/salt.states.user.html works here for present and absent users. Also generates associated user keys via ssh_auth states based on pillar data.
