<?php
/**
 * Plugin Name: WooCommerce PayGlocal Payment
 * Plugin URI: https://payglocal.in
 * Description: This plugin allows any merchant to accept payments with payglocal payment service
 * Author: PayGlocal
 * Author URI: https://payglocal.in
 * Version: 1.0.0
 * Text Domain: woocommerce-payglocal-payment
 * Domain Path: /languages
 *
 */
if (!defined('ABSPATH')) {
    exit;
}

define('WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR', rtrim(plugin_dir_path(__FILE__), '/'));
define('WC_PAYGLOCAL_PAYMENT_PLUGIN_URL', rtrim(plugin_dir_url(__FILE__), '/'));

// Require composer.
require __DIR__ . '/vendor/autoload.php';

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer as SigCompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSLoader;

add_action('plugins_loaded', 'wc_payglocal_payment_gateway_init', 0);

function wc_payglocal_payment_gateway_init()
{
    if (!class_exists('WC_Payment_Gateway')) {
        return;
    }

    class WC_PayGlocal_Payment_Gateway extends WC_Payment_Gateway
    {

        public function __construct()
        {
            $this->id = 'payglocal_payment_gateway';
            $this->icon = apply_filters('woocommerce_payglocal_icon', plugins_url('assets/images/payglocal.png', __FILE__));
            $this->has_fields = false;
            $this->method_title = __('PayGlocal Payments', 'woocommerce-payglocal-payment');
            $this->method_description = __('This plugin allows any merchant to accept payments with payglocal payment service.', 'woocommerce-payglocal-payment');

            $this->init_form_fields();
            $this->init_settings();

            $this->title = $this->get_option('title');
            $this->description = $this->get_option('description');
            $this->payment_mode = $this->get_option('payment_mode');
            $this->merchant_id = $this->get_option('merchant_id');
            $this->public_kid = $this->get_option('public_kid');
            $this->private_kid = $this->get_option('private_kid');
            $this->public_pem = $this->get_option('public_pem');
            $this->private_pem = $this->get_option('private_pem');
            $this->payment_endpoint = ($this->payment_mode) ? 'https://api.prod.payglocal.in' : 'https://api.uat.payglocal.in';
            add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
            add_action('woocommerce_api_wc_payglocal_payment_gateway', array($this, 'check_payglocal_payment_response'));
            add_action('woocommerce_order_details_after_order_table', array($this, 'order_details_after_order_table'), 9);
            add_action('woocommerce_admin_order_data_after_shipping_address', array($this, 'admin_order_data_after_order_details'));
        }

        public function init_form_fields()
        {
            $this->form_fields = array(
                'enabled' => array(
                    'title' => __('Enable/Disable', 'woocommerce-payglocal-payment'),
                    'label' => __('Enable PayGlocal Payment Gateway', 'woocommerce-payglocal-payment'),
                    'description' => '',
                    'type' => 'checkbox',
                    'default' => 'no',
                ),
                'title' => array(
                    'title' => __('Title', 'woocommerce-payglocal-payment'),
                    'description' => __('Payment method title to show on the checkout page.', 'woocommerce-payglocal-payment'),
                    'type' => 'text',
                    'default' => __('PayGlocal Payment', 'woocommerce-payglocal-payment'),
                    'desc_tip' => false,
                    'required' => true,
                ),
                'description' => array(
                    'title' => __('Description', 'woocommerce-payglocal-payment'),
                    'description' => __('Payment description to show on the checkout page.', 'woocommerce-payglocal-payment'),
                    'type' => 'text',
                    'default' => __('You will be redirected to payglocal hosted payment page.', 'woocommerce-payglocal-payment'),
                    'desc_tip' => false,
                ),
                'payment_mode' => array(
                    'title' => __('Payment Mode', 'woocommerce-payglocal-payment'),
                    'description' => __('Chose payglocal payment mode ', 'woocommerce-knet-payment'),
                    'type' => 'select',
                    'default' => '0',
                    'options' => array(
                        '1' => __('Live', 'woocommerce-payglocal-payment'),
                        '0' => __('Sandbox', 'woocommerce-payglocal-payment'),
                    )
                ),
                'merchant_id' => array(
                    'title' => __('Merchant ID', 'woocommerce-payglocal-payment'),
                    'type' => 'text',
                    'description' => __('Enter a merchant id which is provided by payglocal.', 'woocommerce-payglocal-payment'),
                    'default' => '',
                    'desc_tip' => false,
                ),
                'public_kid' => array(
                    'title' => __('Public KID', 'woocommerce-payglocal-payment'),
                    'type' => 'password',
                    'description' => __('Enter a public kid which is provided by payglocal.', 'woocommerce-payglocal-payment'),
                    'default' => '',
                    'desc_tip' => false,
                ),
                'private_kid' => array(
                    'title' => __('Private KID', 'woocommerce-payglocal-payment'),
                    'type' => 'password',
                    'description' => __('Enter a private kid which is provided by payglocal.', 'woocommerce-payglocal-payment'),
                    'default' => '',
                    'desc_tip' => false,
                ),
                'public_pem' => array(
                    'title' => __('Public Pem', 'woocommerce-payglocal-payment'),
                    'type' => 'file',
                    'description' => __('Upload a public pem file which is provided by payglocal.', 'woocommerce-payglocal-payment'),
                    'default' => '',
                    'desc_tip' => false,
                ),
                'private_pem' => array(
                    'title' => __('Private Pem', 'woocommerce-payglocal-payment'),
                    'type' => 'file',
                    'description' => __('Upload a private pem file which is provided by payglocal.', 'woocommerce-payglocal-payment'),
                    'default' => '',
                    'desc_tip' => false,
                ),
            );
        }

        public function generate_file_html($key, $data)
        {
            $field_key = $this->get_field_key($key);
            $defaults = array(
                'title' => '',
                'disabled' => false,
                'class' => '',
                'css' => '',
                'placeholder' => '',
                'type' => 'text',
                'desc_tip' => false,
                'description' => '',
                'custom_attributes' => array(),
            );

            $data = wp_parse_args($data, $defaults);
            ob_start();

            ?>
            <tr valign="top">
                <th scope="row" class="titledesc">
                    <label for="<?php echo esc_attr($field_key); ?>"><?php echo wp_kses_post($data['title']); ?> <?php echo $this->get_tooltip_html($data); // WPCS: XSS ok.     ?></label>
                </th>
                <td class="forminp">
                    <fieldset>
                        <legend class="screen-reader-text"><span><?php echo wp_kses_post($data['title']); ?></span></legend>
                        <input class="input-text regular-input <?php echo esc_attr($data['class']); ?>" type="<?php echo esc_attr($data['type']); ?>" name="<?php echo esc_attr($field_key); ?>" id="<?php echo esc_attr($field_key); ?>" style="<?php echo esc_attr($data['css']); ?>" value="" placeholder="<?php echo esc_attr($data['placeholder']); ?>" <?php disabled($data['disabled'], true); ?> <?php echo $this->get_custom_attribute_html($data); // WPCS: XSS ok.     ?> />
                        <?php echo esc_attr($this->get_option($key)); ?>
                        <?php echo $this->get_description_html($data); // WPCS: XSS ok. ?>
                    </fieldset>
                </td>
            </tr>
            <?php
            return ob_get_clean();
        }

        public function process_admin_options()
        {
            $current_public_pem = $this->public_pem;
            $current_private_pem = $this->private_pem;

            parent::process_admin_options();

            $public_pem_name = $_FILES['woocommerce_payglocal_payment_gateway_public_pem']['name'];
            if (!empty($public_pem_name)) {
                if (file_exists(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->public_pem)) {
                    wp_delete_file(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->public_pem);
                }
                if (move_uploaded_file($_FILES['woocommerce_payglocal_payment_gateway_public_pem']['tmp_name'], WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $public_pem_name)) {
                    $this->update_option('public_pem', $public_pem_name);
                }
            } else {
                $this->update_option('public_pem', $current_public_pem);
            }

            $private_pem_name = $_FILES['woocommerce_payglocal_payment_gateway_private_pem']['name'];
            if (!empty($private_pem_name)) {
                if (file_exists(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->private_pem)) {
                    wp_delete_file(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->private_pem);
                }
                if (move_uploaded_file($_FILES['woocommerce_payglocal_payment_gateway_private_pem']['tmp_name'], WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $private_pem_name)) {
                    $this->update_option('private_pem', $private_pem_name);
                }
            } else {
                $this->update_option('private_pem', $current_private_pem);
            }
        }

        public function process_payment($order_id)
        {
            $payment = $this->createPayGlSPaymentUrl($order_id);
            if (isset($payment['data']['redirectUrl']) && array_key_exists('redirectUrl', $payment['data'])) {
                $order = wc_get_order($order_id);
                $order->update_meta_data('_payglocal_gid', $payment['gid']);
                $order->save();
                return array(
                    'result' => 'success',
                    'redirect' => $payment['data']['redirectUrl']
                );
            } else {
                //$message = $payment['errors']['detailedMessage'];
                //$message = $payment['errors']['displayMessage'];
                $message = __('Unfortunately your order cannot be processed as an error has occured. Please contact site owner.', 'woocommerce-payglocal-payment');
                wc_add_notice($message, 'error');
            }
        }

        public function createPayGlSPaymentUrl($order_id)
        {
            $jweToken = $this->createPayGlSPaymentJweToken($order_id);
            $jwsToken = $this->createPayGlSPaymentJwsToken($jweToken);

            $curl = curl_init();
            curl_setopt_array($curl, array(
                CURLOPT_URL => $this->payment_endpoint . '/gl/v1/payments/initiate/paycollect',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 0,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $jweToken,
                CURLOPT_HTTPHEADER => array(
                    'x-gl-token-external: ' . $jwsToken,
                    'Content-Type: text/plain'
                ),
            ));

            $response = curl_exec($curl);
            $data = json_decode($response, true);
            curl_close($curl);

            return $data;
        }

        protected function createPayGlSPaymentJweToken($order_id)
        {
            $keyEncryptionAlgorithmManager = new AlgorithmManager([
                new RSAOAEP256(),
            ]);
            $contentEncryptionAlgorithmManager = new AlgorithmManager([
                new A128CBCHS256(),
            ]);
            $compressionMethodManager = new CompressionMethodManager([
                new Deflate(),
            ]);
            $jweBuilder = new JWEBuilder(
                $keyEncryptionAlgorithmManager,
                $contentEncryptionAlgorithmManager,
                $compressionMethodManager
            );

            $key = JWKFactory::createFromKeyFile(
                    WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->public_pem,
                    null,
                    [
                        'kid' => $this->public_kid,
                        'use' => 'enc',
                        'alg' => 'RSA-OAEP-256',
                    ]
            );
            $header = [
                'issued-by' => $this->merchant_id,
                'enc' => 'A128CBC-HS256',
                'exp' => 30000,
                'iat' => (string) round(microtime(true) * 1000),
                'alg' => 'RSA-OAEP-256',
                'kid' => $this->public_kid,
            ];

            $payload = $this->createPayGlSPaymentDatas($order_id);

            $jwe = $jweBuilder
                ->create()
                ->withPayload($payload)
                ->withSharedProtectedHeader($header)
                ->addRecipient($key)
                ->build();

            $serializer = new CompactSerializer();
            $token = $serializer->serialize($jwe, 0);

            return $token;
        }

        protected function createPayGlSPaymentJwsToken($jweToken)
        {
            $algorithmManager = new AlgorithmManager([
                new RS256(),
            ]);

            $jwsBuilder = new JWSBuilder(
                $algorithmManager
            );

            $jwskey = JWKFactory::createFromKeyFile(
                    WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->private_pem,
                    null,
                    [
                        'kid' => $this->private_kid,
                        'use' => 'sig'
                    //'alg' => 'RSA-OAEP-256',
                    ]
            );

            $jwsheader = [
                'issued-by' => $this->merchant_id,
                'is-digested' => 'true',
                'alg' => 'RS256',
                'x-gl-enc' => 'true',
                'x-gl-merchantId' => $this->merchant_id,
                'kid' => $this->private_kid
            ];

            $hashedPayload = base64_encode(hash('sha256', $jweToken, $BinaryOutputMode = true));

            $jwspayload = json_encode([
                'digest' => $hashedPayload,
                'digestAlgorithm' => "SHA-256",
                'exp' => 300000,
                'iat' => (string) round(microtime(true) * 1000)
            ]);

            $jws = $jwsBuilder
                ->create()
                ->withPayload($jwspayload)
                ->addSignature($jwskey, $jwsheader)
                ->build();

            $jwsserializer = new \Jose\Component\Signature\Serializer\CompactSerializer(); // The serializer
            $jwstoken = $jwsserializer->serialize($jws, 0);

            return $jwstoken;
        }

        protected function createPayGlSPaymentDatas($order_id)
        {
            $order = wc_get_order($order_id);

            $data = [
                "merchantTxnId" => $order->id . '#' . $this->createPayGlSRandomString(16),
                "merchantUniqueId" => $order->id . '#' . $this->createPayGlSRandomString(16),
                "paymentData" => array(
                    "totalAmount" => $order->get_total(),
                    "txnCurrency" => $order->get_currency(),
                    "billingData" => array(
                        "firstName" => $order->get_billing_first_name(),
                        "lastName" => $order->get_billing_last_name(),
                        "addressStreet1" => $order->get_billing_address_1(),
                        "addressStreet2" => $order->get_billing_address_2(),
                        "addressCity" => $order->get_billing_city(),
                        "addressState" => $order->get_billing_state(),
                        "addressPostalCode" => $order->get_billing_postcode(),
                        "addressCountry" => $order->get_billing_country(),
                        "emailId" => $order->get_billing_email()
                    )
                ),
                "merchantCallbackURL" => WC()->api_request_url('WC_PayGlocal_Payment_Gateway')
            ];

            return json_encode($data);
        }

        protected function createPayGlSRandomString($length = 16)
        {
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $charactersLength = strlen($characters);
            $randomString = '';
            for ($i = 0; $i < $length; $i++) {
                $randomString .= $characters[rand(0, $charactersLength - 1)];
            }
            return $randomString;
        }

        public function check_payglocal_payment_response()
        {
            $response = $_POST;
            if (isset($response['x-gl-token']) && array_key_exists('x-gl-token', $response)) {
                $payment = $this->verifyPayGlSPayment($response['x-gl-token']);
                if (isset($payment['merchantUniqueId']) && array_key_exists('merchantUniqueId', $payment)) {
                    list($order_id, ) = explode('#', $payment['merchantUniqueId']);
                    $order = wc_get_order($order_id);
                    if (isset($payment['status']) && $payment['status'] == 'SENT_FOR_CAPTURE') {
                        $order->update_status('processing');
                        $order->update_meta_data('_payglocal_gid', $payment['gid']);
                        $order->update_meta_data('_payglocal_merchantid', $payment['merchantUniqueId']);
                        $order->update_meta_data('_payglocal_iat', $payment['iat']);
                        $order->save();
                        WC()->cart->empty_cart();
                        $redirect_url = esc_url($this->get_return_url($order));
                        wp_redirect($redirect_url);
                        exit;
                    } else {
                        $order->update_status('failed');
                        $order->update_meta_data('_payglocal_gid', $payment['gid']);
                        $order->update_meta_data('_payglocal_merchantid', $payment['merchantUniqueId']);
                        $order->update_meta_data('_payglocal_iat', $payment['iat']);
                        $order->save();
                        $message = __('Unfortunately your order cannot be processed as an error has occured. Please contact site owner.', 'woocommerce-payglocal-payment');
                        wc_add_notice($message, 'error');
                        $redirect_url = esc_url(wc_get_page_permalink('checkout'));
                        wp_redirect($redirect_url);
                        exit;
                    }
                } else {
                    $payment = $this->getPayGlSPaymentOrderStatus($payment['statusUrl']);
                    list($order_id, ) = explode('#', $payment['data']['merchantTxnId']);
                    $order = wc_get_order($order_id);
                    $order->update_status('failed');
                    $order->update_meta_data('_payglocal_gid', $payment['gid']);
                    $order->save();
                    $message = __('Unfortunately your order cannot be processed as an error has occured. Please contact site owner.', 'woocommerce-payglocal-payment');
                    wc_add_notice($message, 'error');
                    $redirect_url = esc_url(wc_get_page_permalink('checkout'));
                    wp_redirect($redirect_url);
                    exit;
                }
            } else {
                $redirect_url = esc_url(wc_get_page_permalink('checkout'));
                wp_redirect($redirect_url);
                exit;
            }
        }

        protected function verifyPayGlSPayment($token)
        {
            $algorithmManager = new AlgorithmManager([
                new RS256(),
            ]);
            $jwsVerifier = new JWSVerifier(
                $algorithmManager
            );
            $jwk = JWKFactory::createFromKeyFile(
                    WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $this->public_pem,
                    null,
                    [
                        'kid' => $this->public_kid,
                        'use' => 'sig'
                    //'alg' => 'RSA-OAEP-256',
                    ]
            );
            $serializerManager = new JWSSerializerManager([
                new SigCompactSerializer(),
            ]);

            $jws = $serializerManager->unserialize($token);
            $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

            $headerCheckerManager = $payload = null;

            $jwsLoader = new JWSLoader(
                $serializerManager,
                $jwsVerifier,
                $headerCheckerManager
            );

            $jws = $jwsLoader->loadAndVerifyWithKey($token, $jwk, $signature, $payload);

            return json_decode($jws->getPayload(), true);
        }

        protected function getPayGlSPaymentOrderStatus($url)
        {
            $curl = curl_init();
            curl_setopt_array($curl, array(
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 0,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => 'GET',
            ));

            $response = curl_exec($curl);
            $data = json_decode($response, true);
            curl_close($curl);

            return $data;
        }

        public function admin_order_data_after_order_details($order)
        {
            $payment_method = $order->get_payment_method();
            if ('payglocal_payment_gateway' == $payment_method) {
                ob_start();
                echo "<h3>" . __('PayGlocal Payment Info', 'woocommerce-payglocal-payment') . "</h3>";
                echo "<p>" . __('Gid', 'woocommerce-payglocal-paymen') . " : " . $order->get_meta('_payglocal_gid') . "</p>";
                echo "<p>" . __('Merchant Unique Id', 'woocommerce-payglocal-paymen') . " : " . $order->get_meta('_payglocal_merchantid') . "</p>";
            }
        }

        public function order_details_after_order_table($order)
        {
            $payment_method = $order->get_payment_method();
            if ('payglocal_payment_gateway' == $payment_method) {

                ?>
                <h2 style="margin-top:20px;" class="woocommerce-order-details__title"><?php _e('PayGlocal Payment Info', 'woocommerce-payglocal-payment'); ?></h2>
                <table class="<?php echo $this->id; ?>_table" cellpadding="0" cellspacing="0">
                    <tr>
                        <td><?php _e('Gid', 'woocommerce-payglocal-payment'); ?>:</td>
                        <td><?php echo $order->get_meta('_payglocal_gid'); ?></td>
                    </tr>
                    <tr>
                        <td><?php _e('Merchant Unique Id', 'woocommerce-payglocal-payment'); ?>:</td>
                        <td><?php echo $order->get_meta('_payglocal_merchantid'); ?></td>
                    </tr>
                </table>
                <?php
            }
        }
    }

    function wc_payglocal_payment_gateway_class($methods)
    {
        $methods[] = 'WC_PayGlocal_Payment_Gateway';
        return $methods;
    }
    add_filter('woocommerce_payment_gateways', 'wc_payglocal_payment_gateway_class');

    function wc_payglocal_settings_link($links)
    {
        $plugin_links[] = '<a href="' . admin_url('admin.php?page=wc-settings&tab=checkout&section=payglocal_payment_gateway') . '">' . __('Settings', 'woocommerce-payglocal-payment') . '</a>';
        return array_merge($plugin_links, $links);
    }
    add_filter("plugin_action_links_" . plugin_basename(__FILE__), 'wc_payglocal_settings_link');
}

function wc_payglocal_deactivation()
{
    $payment_gateway = WC()->payment_gateways->payment_gateways()['payglocal_payment_gateway'];
    
    $payment_gateway->update_option('payment_mode', '');
    $payment_gateway->update_option('merchant_id', '');
    $payment_gateway->update_option('public_kid', '');
    $payment_gateway->update_option('private_kid', '');

    if (file_exists(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $payment_gateway->public_pem)) {
        wp_delete_file(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $payment_gateway->public_pem);
    }
    if (file_exists(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $payment_gateway->private_pem)) {
        wp_delete_file(WC_PAYGLOCAL_PAYMENT_PLUGIN_DIR . '/' . $payment_gateway->private_pem);
    }
    
    $payment_gateway->update_option('public_pem', '');
    $payment_gateway->update_option('private_pem', '');
}
register_deactivation_hook(__FILE__, 'wc_payglocal_deactivation');
